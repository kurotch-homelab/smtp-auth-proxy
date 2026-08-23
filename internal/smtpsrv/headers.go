package smtpsrv

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/textproto"
	"strings"
)

// Header manipulation errors.
var (
	// ErrNoHeaderSeparator means the message never had a blank line, so it has
	// no body and arguably no headers either.
	ErrNoHeaderSeparator = errors.New("smtpsrv: message has no blank line separating headers from body")
	// ErrHeaderTooLarge means the header block exceeded the allowed size.
	ErrHeaderTooLarge = errors.New("smtpsrv: message headers are too large")
)

// maxHeaderBytes bounds how much of a message is treated as headers. RFC 5322
// sets no limit, but a message whose headers run to a megabyte is not something
// a printer produced.
const maxHeaderBytes = 1 << 20 // 1 MiB

// crlf is the line ending required on the wire.
var crlf = []byte("\r\n")

// message is a submission split into a header block and an untouched body.
//
// The body is never re-encoded. Round-tripping MIME through a parser can change
// transfer encodings, re-fold headers and reorder parts, any of which alters a
// message that was already valid — and if the sender happened to sign it, would
// invalidate the signature.
type message struct {
	// raw is the whole original message.
	raw []byte
	// headerEnd is the offset just past the blank line.
	headerEnd int
	// header is the parsed header block, for reading.
	header textproto.MIMEHeader
	// keys preserves the original header order and casing.
	keys []string
}

// parseMessage splits a message and parses its header block.
func parseMessage(raw []byte) (*message, error) {
	end, err := findHeaderEnd(raw)
	if err != nil {
		return nil, err
	}
	if end > maxHeaderBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrHeaderTooLarge, end)
	}

	// textproto needs the block to end with a blank line to know it is done.
	block := make([]byte, 0, end+2)
	block = append(block, raw[:end]...)

	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(block)))
	header, err := r.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("smtpsrv: parsing message headers: %w", err)
	}

	return &message{
		raw:       raw,
		headerEnd: end,
		header:    header,
		keys:      headerOrder(raw[:end]),
	}, nil
}

// findHeaderEnd returns the offset just past the blank line that ends the
// header block, accepting either CRLF or bare LF line endings — devices are not
// consistent about this, and rejecting the sloppy ones would break exactly the
// hardware this proxy exists for.
func findHeaderEnd(raw []byte) (int, error) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return i + 4, nil
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return i + 2, nil
	}
	return 0, ErrNoHeaderSeparator
}

// headerOrder lists the field names in the order they appeared.
func headerOrder(block []byte) []string {
	var keys []string
	for _, line := range bytes.Split(block, []byte("\n")) {
		// Continuation lines belong to the previous field.
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if i := bytes.IndexByte(line, ':'); i > 0 {
			keys = append(keys, string(bytes.TrimSpace(line[:i])))
		}
	}
	return keys
}

// Get returns the first value of a header, or "".
func (m *message) Get(key string) string { return m.header.Get(key) }

// Body returns the message body, unmodified.
func (m *message) Body() []byte { return m.raw[m.headerEnd:] }

// headerEdit describes one change to the header block.
type headerEdit struct {
	// Key is the field name, canonicalized on use.
	Key string
	// Value replaces the field's current value. An empty value deletes it.
	Value string
	// Prepend puts a new field at the very top instead of in place. Received
	// headers belong at the top, in the order they were added.
	Prepend bool
}

// rewriteHeaders applies edits and returns the reassembled message.
//
// Fields not mentioned keep their original bytes, including folding and
// ordering, so a message is changed as little as the edits require.
func (m *message) rewriteHeaders(edits []headerEdit) []byte {
	replace := make(map[string]string, len(edits))
	var prepends []headerEdit

	for _, e := range edits {
		if e.Prepend {
			prepends = append(prepends, e)
			continue
		}
		replace[textproto.CanonicalMIMEHeaderKey(e.Key)] = e.Value
	}

	var out bytes.Buffer
	out.Grow(len(m.raw) + 256)

	for _, e := range prepends {
		writeHeaderLine(&out, e.Key, e.Value)
	}

	// Walk the original block line by line so untouched fields are copied
	// verbatim, continuations included.
	var (
		skipping bool
		seen     = make(map[string]bool, len(replace))
	)
	for _, line := range splitLines(m.raw[:m.headerEnd]) {
		trimmed := bytes.TrimRight(line, "\r\n")

		// The blank line that ends the block.
		if len(trimmed) == 0 {
			break
		}

		isContinuation := trimmed[0] == ' ' || trimmed[0] == '\t'
		if isContinuation {
			if !skipping {
				out.Write(trimmed)
				out.Write(crlf)
			}
			continue
		}

		skipping = false
		colon := bytes.IndexByte(trimmed, ':')
		if colon <= 0 {
			// Not a header line at all; keep it rather than silently dropping it.
			out.Write(trimmed)
			out.Write(crlf)
			continue
		}

		key := textproto.CanonicalMIMEHeaderKey(string(bytes.TrimSpace(trimmed[:colon])))
		newValue, edited := replace[key]
		if !edited {
			out.Write(trimmed)
			out.Write(crlf)
			continue
		}

		seen[key] = true
		skipping = true
		// An empty replacement deletes the field.
		if newValue != "" {
			writeHeaderLine(&out, key, newValue)
		}
	}

	// Add fields the message did not already have.
	for key, value := range replace {
		if !seen[key] && value != "" {
			writeHeaderLine(&out, key, value)
		}
	}

	out.Write(crlf)
	out.Write(m.Body())
	return out.Bytes()
}

func writeHeaderLine(buf *bytes.Buffer, key, value string) {
	buf.WriteString(textproto.CanonicalMIMEHeaderKey(key))
	buf.WriteString(": ")
	// A newline in a header value would inject a header of the attacker's
	// choosing, so collapse anything that could end the line.
	buf.WriteString(sanitizeHeaderValue(value))
	buf.Write(crlf)
}

// sanitizeHeaderValue strips CR and LF, which is what makes header injection
// possible: a value containing "\r\nBcc: attacker@evil.example" would otherwise
// become a real Bcc field.
func sanitizeHeaderValue(v string) string {
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	replacer := strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ")
	return strings.TrimSpace(replacer.Replace(v))
}

// splitLines splits on LF, keeping the terminator on each line.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

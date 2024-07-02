package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"testing"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/writer"
	"github.com/stretchr/testify/require"
)

type fakeWriteCloserReadSeeker struct {
	*bytes.Buffer
}

func (f *fakeWriteCloserReadSeeker) Close() error {
	return nil
}

func (f *fakeWriteCloserReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (f *fakeWriteCloserReadSeeker) Read(p []byte) (int, error) {
	return f.Buffer.Read(p)
}

func TestSerializeDiffFormats(t *testing.T) {
	for _, formatSource := range formats.List {
		for _, formatDst := range formats.List {
			files := findFiles(t, formatSource)
			r := reader.New()

			w := writer.New(
				writer.WithFormat(formatDst),
			)
			for _, fname := range files {
				fname_base := path.Base(fname)
				test_name := fmt.Sprintf("diff-%s/%s/%s", formatSource, formatDst, fname_base)
				t.Run(test_name, func(t *testing.T) {

					golden := readProtobom(t, fname+".proto")

					wr := &fakeWriteCloserReadSeeker{
						Buffer: new(bytes.Buffer),
					}
					err := w.WriteStream(golden, wr)
					require.NoError(t, err)

					goldenSut, err := r.ParseStreamWithOptions(wr, &reader.Options{
						Format: formatDst,
					})
					require.NoError(t, err)

					t.Logf("golden: %s, source-format: %s, dst-format: %s", fname+".proto", formatSource, formatDst)

					goldenNl := golden.NodeList
					goldenSutNl := goldenSut.NodeList
					goldenNlDiff := goldenNl.Diff(goldenSutNl)

					if goldenNlDiff.Nodes.Added != nil ||
						goldenNlDiff.Nodes.Removed != nil ||
						goldenNlDiff.Edges.Added != nil ||
						goldenNlDiff.Edges.Removed != nil ||
						len(goldenNlDiff.RootElements.Added) != 0 ||
						len(goldenNlDiff.RootElements.Removed) != 0 {

						godldenNlDiffJson, err := json.MarshalIndent(goldenNlDiff, "", "  ")
						require.NoError(t, err)
						t.Logf(">>>>>>>>>>>\n%s\n<<<<<<<<<<<<<", string(godldenNlDiffJson))

					}

					t.Run(
						fmt.Sprintf("diff-%s-%s-%s->%s-%s-%s", formatSource.Type(), formatSource.Version(), formatSource.Encoding(),
							formatDst.Type(), formatDst.Version(), formatDst.Encoding()),
						func(t *testing.T) {
							require.Empty(t, goldenNlDiff)
						},
					)
				})
			}
		}
	}
}

package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
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

func serializedDiffFormats(t *testing.T, w *writer.Writer, r *reader.Reader, formatSource formats.Format, formatDst formats.Format, fname string, diffDir bool) {
	golden := readProtobom(t, fname+".proto")

	wr := &fakeWriteCloserReadSeeker{
		Buffer: new(bytes.Buffer),
	}
	err := w.WriteStream(golden, wr)
	require.NoError(t, err)
	storeWritten := wr.Bytes()

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
		if diffDir {
			createDiffDir(t, path.Base(fname), formatSource, formatDst, storeWritten, goldenNlDiff)
		}

	}

	t.Run(
		fmt.Sprintf("diff-%s-%s-%s->%s-%s-%s", formatSource.Type(), formatSource.Version(), formatSource.Encoding(),
			formatDst.Type(), formatDst.Version(), formatDst.Encoding()),
		func(t *testing.T) {
			require.Empty(t, goldenNlDiff)
		},
	)
}

func TestSerializeDiffTable(t *testing.T) {
	tests := []struct {
		name         string
		formatSource formats.Format
		formatDst    formats.Format
		filesCount   int
		filesSource  []string
	}{
		{
			name:         "cdx_1.5_to_spdx_2.3",
			formatSource: "application/vnd.cyclonedx+json;version=1.5",
			formatDst:    "text/spdx+json;version=2.3",
			filesSource: []string{
				"testdata/cyclonedx/1.5/json/bom-1.5.json",
				// "testdata/cyclonedx/1.5/json/syft-0.96.0_plone-5.2.cdx.json",
				// "testdata/cyclonedx/1.5/json/syft-0.96.0_rails-5.0.0.cdx.json",
			},
		},
		{
			name:         "spdx_2.3_to_cdx_1.5",
			formatSource: "text/spdx+json;version=2.3",
			formatDst:    "application/vnd.cyclonedx+json;version=1.5",
			filesSource: []string{
				// "testdata/spdx/2.3/json/bom-v0.4.1_cirros-0.4.0.spdx.json",
				"testdata/spdx/2.3/json/curl.spdx.json",
				// "testdata/spdx/2.3/json/kubernetes_kubernetes_d61cbac69aae97db1839bd2e0e86d68f26b353a7.json",
				// "testdata/spdx/2.3/json/trivy-0.42.1_mageia-5.1.spdx.json",
			},
		},
	}
	fmt.Println("Formats: ", formats.List)
	for _, test := range tests {

		foundFiles := findFiles(t, test.formatSource)
		t.Logf("Found files: %s", foundFiles)

		r := reader.New()

		w := writer.New(
			writer.WithFormat(test.formatDst),
		)

		for _, fname := range test.filesSource {
			t.Logf(">>>>>>>>>>> Running '%s' On: %s <<<<<<<<<<<<<", test.name, fname)

			fname_base := path.Base(fname)
			test_name := fmt.Sprintf("diff-%s/%s/%s", test.formatSource, test.formatDst, fname_base)
			t.Run(test_name, func(t *testing.T) {
				serializedDiffFormats(t, w, r, test.formatSource, test.formatDst, fname, true)
			})
			break
		}
	}

}

// Conformance off all formats wil not pass in the current state
// func TestSerializeDiffAll(t *testing.T) {
// 	for _, formatSource := range formats.List {
// 		for _, formatDst := range formats.List {
// 			fmt.Println("formatSource: ", formatSource)

// 			files := findFiles(t, formatSource)
// 			r := reader.New()

// 			w := writer.New(
// 				writer.WithFormat(formatDst),
// 			)
// 			for _, fname := range files {

// 				fname_base := path.Base(fname)
// 				test_name := fmt.Sprintf("diff-%s/%s/%s", formatSource, formatDst, fname_base)
// 				t.Run(test_name, func(t *testing.T) {
// 					serializedDiffFormats(t, w, r, formatSource, formatDst, fname)
// 				})
// 				break
// 			}
// 		}

// 	}
// }

func createDiffDir(t *testing.T, fname string, src, dst formats.Format, written []byte, diff sbom.NodeListDiff) {
	tmpDir := ".tmp/diff"
	err := os.MkdirAll(tmpDir, os.ModePerm)
	require.NoError(t, err)

	diffDir := path.Join(tmpDir, fmt.Sprintf("%s-%s/%s-%s/%s", src.Type(), src.Version(), dst.Type(), dst.Version(), fname))
	err = os.MkdirAll(diffDir, os.ModePerm)
	require.NoError(t, err)

	diffJson, err := json.MarshalIndent(diff, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(path.Join(diffDir, "diff.json"), diffJson, os.ModePerm)
	require.NoError(t, err)

	err = os.WriteFile(path.Join(diffDir, fmt.Sprintf("dst.%s.json", dst.Type())), written, os.ModePerm)
	require.NoError(t, err)

}

package converter

import (
	"fmt"

	"ocm.software/open-component-model/bindings/go/ctf"
	"ocm.software/open-component-model/bindings/go/oci"
	ocictf "ocm.software/open-component-model/bindings/go/oci/ctf"
)

func createRepository(ctfFolderPath string) (oci.ComponentVersionRepository, error) {
	archive, err := ctf.OpenCTFFromOSPath(ctfFolderPath, ctf.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("failed to open CTF archive: %w", err)
	}

	repo, err := oci.NewRepository(ocictf.WithCTF(ocictf.NewFromCTF(archive)))
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI repository: %w", err)
	}
	// repo.GetComponentVersion(context.Background(), "github.com/acme.org/parent", "1.0.0") -> value, error
	return repo, nil
}

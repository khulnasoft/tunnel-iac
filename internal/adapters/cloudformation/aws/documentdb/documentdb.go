package documentdb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"
	"github.com/khulnasoft/tunnel-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) documentdb.DocumentDB {
	return documentdb.DocumentDB{
		Clusters: getClusters(cfFile),
	}
}

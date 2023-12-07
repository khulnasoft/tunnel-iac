package sqs

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/khulnasoft/tunnel-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) sqs.SQS {
	return sqs.SQS{
		Queues: getQueues(cfFile),
	}
}

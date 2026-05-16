package services

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func IsNotFoundError(err error) bool {
	var noSuchKey *types.NoSuchKey
	var notFound *types.NotFound
	var noSuchBucket *types.NoSuchBucket

	return errors.As(err, &noSuchKey) || errors.As(err, &notFound) || errors.As(err, &noSuchBucket)
}

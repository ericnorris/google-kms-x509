load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "generate-csr.go",
        "generate-root-ca.go",
        "sign-intermediate-ca.go",
    ],
    importpath = "github.com/ericnorris/google-kms-x509/internal/cli",
    visibility = ["//:__subpackages__"],
    deps = [
        "//kmssign:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
    ],
)

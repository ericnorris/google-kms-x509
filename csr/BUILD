load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "generate.go",
        "kms-signer.go",
    ],
    importpath = "github.com/ericnorris/google-kms-x509/csr",
    visibility = ["//visibility:public"],
    deps = [
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@org_golang_google_genproto//googleapis/cloud/kms/v1:go_default_library",
    ],
)

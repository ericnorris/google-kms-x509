load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "csr.go",
        "main.go",
    ],
    importpath = "github.com/ericnorris/google-kms-ca/cmd/google-kms-ca",
    visibility = ["//visibility:private"],
    deps = ["@com_github_spf13_cobra//:go_default_library"],
)

go_binary(
    name = "google-kms-ca",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
)

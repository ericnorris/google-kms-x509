load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "csr.go",
        "main.go",
    ],
    importpath = "github.com/ericnorris/google-kms-x509/cmd/google-kms-x509",
    visibility = ["//visibility:private"],
    deps = [
        "//csr:go_default_library",
        "@com_github_spf13_cobra//:go_default_library",
    ],
)

go_binary(
    name = "google-kms-x509",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
)

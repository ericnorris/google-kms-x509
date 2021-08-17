load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "crl-dist-flags.go",
        "days-flags.go",
        "generate.go",
        "key-flags.go",
        "main.go",
        "out-flags.go",
        "sign.go",
        "subject-flags.go",
    ],
    importpath = "github.com/ericnorris/google-kms-x509/cmd/google-kms-x509",
    visibility = ["//visibility:private"],
    x_defs = {
        "Version": "{STABLE_GIT_VERSION}",
    },
    deps = [
        "//internal/cli:go_default_library",
        "@com_github_spf13_cobra//:go_default_library",
    ],
)

go_binary(
    name = "google-kms-x509",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
)

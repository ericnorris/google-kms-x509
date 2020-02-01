load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["main.go"],
    importpath = "github.com/ericnorris/google-kms-ca/cmd/google-kms-ca",
    visibility = ["//visibility:private"],
)

go_binary(
    name = "google-kms-ca",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
)

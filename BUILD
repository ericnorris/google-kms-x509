load("@bazel_gazelle//:def.bzl", "gazelle")

# gazelle:prefix github.com/ericnorris/google-kms-x509
# gazelle:proto disable_global
# gazelle:build_file_name BUILD
gazelle(name = "gazelle")

load("@io_bazel_rules_go//go:def.bzl", "nogo")

nogo(
    name = "nogo",
    vet = True,
    deps = [],
    visibility = ["//visibility:public"],
)

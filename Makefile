.PHONY: all test clean
.PHONY: generate-build-files update-dependencies

all:
	@bazel build //...

test:
	@bazel test //...

clean:
	@bazel clean

generate-build-files:
	@bazel run //:gazelle

update-dependencies:
	@bazel run //:gazelle -- update-repos \
		-from_file go.mod \
		-build_file_proto_mode disable_global \
		-to_macro go-repositories.bzl%go_repositories

load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "runsccmd",
    srcs = [
        "runsc.go",
        "utils.go",
    ],
    visibility = ["//pkg/shim:__subpackages__"],
    deps = [
        "@com_github_containerd_go_runc//:go_default_library",
        "@com_github_containerd_log//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

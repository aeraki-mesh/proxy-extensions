load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "config_lib",
    repository = "@envoy",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":dubbo_rbac_filter",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "dubbo_rbac_filter",
    repository = "@envoy",
    srcs = ["dubbo_rbac_filter.cc"],
    hdrs = ["dubbo_rbac_filter.h"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy//source/exe:envoy_common_lib",
    ],
)

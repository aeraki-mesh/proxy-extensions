# Istio Proxy Extensions
This project provides some extensions for Istio and Envoy.
- dubbo_rbac: Role based access control (RBAC) filter for dubbo.

# How to use

## Build with Istio-Proxy

1. Add this project as a dependency to the `WORKSPACE` file of the Istio proxy.
```bazel
EXTENSIONS_SHA = "19fee7e63c6d09956b70c43f2bea205b0f6952f4"

EXTENSIONS_SHA256 = "ceec1d7d187e4a115baf6c771d95e08d83a6d13ef3b023ebb0c797b300924d24"

EXTENSIONS_ORG = "aeraki-framework"

EXTENSIONS_REPO = "proxy-extensions"

http_archive(
    name = "aeraki-extensions",
    sha256 = EXTENSIONS_SHA256,
    strip_prefix = EXTENSIONS_REPO + "-" + EXTENSIONS_SHA,
    url = "https://github.com/" + EXTENSIONS_ORG + "/" + EXTENSIONS_REPO + "/archive/" + EXTENSIONS_SHA + ".tar.gz",
)
```

2. Add deps to `//src/envoy:envoy` target in `src/envoy/BUILD`
```
envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    visibility = ["//visibility:public"],
    deps = [
        "//extensions/access_log_policy:access_log_policy_lib",
        "//extensions/attributegen:attributegen_plugin",
        "//extensions/metadata_exchange:metadata_exchange_lib",
        "//extensions/stackdriver:stackdriver_plugin",
        "//extensions/stats:stats_plugin",
        "//src/envoy/extensions/wasm:wasm_lib",
        "//src/envoy/http/alpn:config_lib",
        "//src/envoy/http/authn:filter_lib",
        "//src/envoy/tcp/forward_downstream_sni:config_lib",
        "//src/envoy/tcp/metadata_exchange:config_lib",
        "//src/envoy/tcp/sni_verifier:config_lib",
        "//src/envoy/tcp/tcp_cluster_rewrite:config_lib",

        # add deps here
        "@aeraki-extensions//src/extensions/network/dubbo_rbac:config_lib",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)
```
3. build istio-proxy `make build_envoy`.

## Build Envoy
1. `bazel build //:envoy`

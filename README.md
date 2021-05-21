# Istio Proxy Extensions
This project provides some extensions for Istio and Envoy.
- dubbo_rbac: Role based access control (RBAC) filter for dubbo.

# How to use

## Build with Istio-Proxy

1. Add this project as a dependency to the `WORKSPACE` file of the Istio proxy.
```bazel
EXTENSIONS_SHA = "4da7b39cf02aa1347f3d405be8efed36c968479d"

EXTENSIONS_SHA256 = "da5d8e3b6a1e5ff47f33249011a2f6c9837764b6f46ef177d8f5813b68cedfa2"

EXTENSIONS_ORG = "aeraki-framework"

EXTENSIONS_REPO = "proxy-extensions"

http_archive(
    name = "proxy-extensions",
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
        "@proxy-extensions//src/extensions/network/dubbo_rbac:config_lib",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)
```
3. build istio-proxy `make build_envoy`.

## Build Envoy
1. `bazel build //:envoy`
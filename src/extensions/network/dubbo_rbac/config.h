#pragma once

#include "src/extensions/network/dubbo_rbac/dubbo_rbac_filter.h"

#include "envoy/extensions/filters/network/rbac/v3/rbac.pb.h"
#include "envoy/extensions/filters/network/rbac/v3/rbac.pb.validate.h"

#include "extensions/filters/network/dubbo_proxy/filters/factory_base.h"
#include "extensions/filters/network/dubbo_proxy/filters/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace DubboProxy {
namespace RBACFilter {

class RoleBasedAccessControlNetworkFilterConfigFactory
    : public DubboFilters::FactoryBase<envoy::extensions::filters::network::rbac::v3::RBAC> {
public:
  RoleBasedAccessControlNetworkFilterConfigFactory() : FactoryBase(DubboRbacFilterName) {}

private:
  DubboFilters::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::rbac::v3::RBAC& proto_config,
      const std::string& stat_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace RBACFilter
} // namespace DubboProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
#pragma once

#include "GView.hpp"
#include <vector>

namespace GView::GenericPlugins::HashAnalyzer
{
struct Config {
    struct {
        std::string ApiKey;
    } VirusTotal;

    std::vector<std::string> PreferredAVs;

    std::string DefaultService;
    bool Loaded;

    void Initialize();
    void Update(AppCUI::Utils::IniSection sect);
    void Save();
};

Config& GetPluginConfig();
} // namespace GView::GenericPlugins::HashAnalyzer

#include "Config.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{
constexpr auto SECTION_NAME        = "Generic.HashAnalyzer";
constexpr auto KEY_VT_API_KEY      = "VirusTotal.Key";
constexpr auto KEY_DEFAULT_SERVICE = "DefaultService";
constexpr auto KEY_PREFERRED_AVS   = "PreferredAVs";

Config config;

Config& GetPluginConfig()
{
    return config;
}

void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini) {
        auto sect               = ini->GetSection(SECTION_NAME);
        this->VirusTotal.ApiKey = sect.GetValue(KEY_VT_API_KEY).ToStringView();
        this->DefaultService    = sect.GetValue(KEY_DEFAULT_SERVICE).ToStringView();
        
        // Parse PreferredAVs
        auto avsStr = sect.GetValue(KEY_PREFERRED_AVS).ToStringView();
        if (!avsStr.empty()) {
            size_t start = 0;
            size_t end;
            while ((end = avsStr.find(',', start)) != std::string_view::npos) {
                 auto token = avsStr.substr(start, end - start);
                 // trim
                 while(token.length()>0 && (token.front()==' ' || token.front()=='\t')) token.remove_prefix(1);
                 while(token.length()>0 && (token.back()==' ' || token.back()=='\t')) token.remove_suffix(1);
                 
                 if (!token.empty()) this->PreferredAVs.emplace_back(token);
                 start = end + 1;
            }
            // last one
            auto token = avsStr.substr(start);
            while(token.length()>0 && (token.front()==' ' || token.front()=='\t')) token.remove_prefix(1);
            while(token.length()>0 && (token.back()==' ' || token.back()=='\t')) token.remove_suffix(1);
            if (!token.empty()) this->PreferredAVs.emplace_back(token);
        }
    }
    this->Loaded = true;
}

void Config::Update(AppCUI::Utils::IniSection sect)
{
    sect.UpdateValue(KEY_VT_API_KEY, "", true);
    sect.UpdateValue(KEY_DEFAULT_SERVICE, "virustotal", true);
    sect.UpdateValue(KEY_PREFERRED_AVS, "", true); 
}

void Config::Save()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini) {
        auto sect                 = ini->GetSection(SECTION_NAME);
        sect[KEY_VT_API_KEY]      = this->VirusTotal.ApiKey;
        sect[KEY_DEFAULT_SERVICE] = this->DefaultService;
        
        // Save PreferredAVs
        if (!this->PreferredAVs.empty()) {
             std::string combined;
             for (size_t i = 0; i < this->PreferredAVs.size(); ++i) {
                 if (i > 0) combined += ", ";
                 combined += this->PreferredAVs[i];
             }
             sect[KEY_PREFERRED_AVS] = combined;
        }

        ini->Save(AppCUI::Application::GetAppSettingsFile());
    }
}
} // namespace GView::GenericPlugins::HashAnalyzer

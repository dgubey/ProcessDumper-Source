// pattern_db.h -- Updated CS2 Signature Database
#pragma once
#include <cstdint>

struct PatDef {
    const char* label;
    const char* pat;       // "AA BB ?? CC" format
    int         dispOff;   // RIP disp32 offset (-1 = no resolution)
    int         instrLen;  // for RIP calc
    int         extraDeref;// post-resolution dereferences
    const char* engineVer; // "*" or "cs2"
    const char* notes;
};

// ---------------------------------------------------------------------------
// Updated CS2 Patterns (client.dll & engine2.dll)
// ---------------------------------------------------------------------------
static const PatDef PATS_CS2[] = {
    // Critical Offsets (1. ÖNEMLİLER)
    { "dwEntityList",             "48 8B 0D ?? ?? ?? ?? 48 89 7C 24 ?? 8B FA 48 8B 81", 3, 7, 0, "cs2", "Entity System List" },
    { "dwLocalPlayerPawn",        "48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8B 0D ?? ?? ?? ?? 48 8B 01", 3, 7, 0, "cs2", "Local Player Pawn" },
    { "dwLocalPlayerController",  "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 4F 8B 88", 3, 7, 0, "cs2", "Local Player Controller" },
    { "dwViewMatrix",             "48 8D 0D ?? ?? ?? ?? 48 C1 E0 06 48 03 C1", 3, 7, 0, "cs2", "World to Screen Matrix" },
    { "dwGlobalVars",             "48 89 0D ?? ?? ?? ?? 48 89 41", 3, 7, 0, "cs2", "Global Variables Struct" },
    { "dwGameEntitySystem",       "48 8B 1D ?? ?? ?? ?? 48 89 5C 24 ?? 48 83 C4", 3, 7, 0, "cs2", "Game Entity System" },
    { "dwGameRules",              "48 89 0D ?? ?? ?? ?? 48 8B 01 FF 50 28", 3, 7, 0, "cs2", "CSGameRules Pointer" },

    // Player Controller & Pawn Netvars
    { "m_hPlayerPawn",            "8B 91 ?? ?? 00 00 83 FA FF 74", 2, 6, -1, "cs2", "Controller -> Pawn Handle" },
    { "m_iHealth",                "8B 93 ?? ?? 00 00 85 D2 7E", 2, 6, -1, "cs2", "Pawn Health (int32)" },
    { "m_iTeamNum",               "8B 83 ?? ?? 00 00 85 C0 74 ?? 83 F8 02", 2, 6, -1, "cs2", "Pawn/Controller Team ID" },
    { "m_vOldOrigin",             "F3 0F 10 83 ?? ?? 00 00 F3 0F 10 8B", 4, 8, -1, "cs2", "Pawn Position Vector3" },
    { "m_angEyeAngles",           "74 ?? 48 8B 03 48 8B CB FF 90 ?? ?? 00 00 0F 28 80", 10, 14, -1, "cs2", "Pawn Eye Angles Vector3" },
    { "m_bIsScoped",              "80 B3 ?? ?? 00 00 00 74 ?? 48 8B 03", 2, 6, -1, "cs2", "Is Player Scoped (bool)" },
    { "m_fFlags",                 "8B 83 ?? ?? 00 00 83 E0 01 89 44 24", 2, 6, -1, "cs2", "Pawn Movement Flags" },
    { "m_hActiveWeapon",          "8B B3 ?? ?? 00 00 83 FE FF 74", 2, 6, -1, "cs2", "Active Weapon Handle" },
    { "m_iClip1",                 "8B 8B ?? ?? 00 00 85 C9 7E", 2, 6, -1, "cs2", "Weapon Current Ammo Clip" },
    { "m_iszPlayerName",          "48 8D 83 ?? ?? 00 00 48 89 44 24 ?? 48 8B 01", 3, 7, -1, "cs2", "Player Name String" },

    // Secondary Offsets (2. DAHA AZ ÖNEMLİLER)
    { "dwForceAttack",            "48 8B 05 ?? ?? ?? ?? 8B DE 89 04 24", 3, 7, 0, "cs2", "Force Attack (+attack)" },
    { "dwForceJump",              "48 8B 05 ?? ?? ?? ?? 8B D8 89 04 24", 3, 7, 0, "cs2", "Force Jump (+jump)" },
    { "dwPlantedC4",              "48 8B 05 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 89 44 24", 3, 7, 0, "cs2", "Planted C4 Pointer" },
    { "dwSensitivity",            "48 8B 05 ?? ?? ?? ?? 48 8B 40 ?? 48 8B 08", 3, 7, 0, "cs2", "Mouse Sensitivity" },

    // Helpers / Strings (3. ÖNEMSİZLER)
    { "xref_EntityList",          "EntityList", -1, 0, 0, "cs2", "String xref" },
    { "xref_LocalPlayer",         "LocalPlayer", -1, 0, 0, "cs2", "String xref" },
    { "xref_ViewMatrix",          "ViewMatrix", -1, 0, 0, "cs2", "String xref" },
};

static const PatDef PATS_UE50[] = {
    { "GWorld",                   "48 8B 05 ?? ?? ?? ?? 48 3B C0 74 ?? 48 8B 08", 3, 7, 0, "ue5", "Engine GWorld Pointer" },
    { "GObjects",                 "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1", 3, 7, 0, "ue5", "FUObjectArray Pointer" },
    { "GNames",                   "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B C0 88 44 24", 3, 7, 0, "ue5", "FNamePool Pointer" },
};

static const PatDef PATS_IL2CPP[] = {
    { "il2cpp_domain",            "48 8B 05 ?? ?? ?? ?? 48 83 C4 20 E9", 3, 7, 0, "il2cpp", "Domain Pointer" },
};

static const PatDef PATS_GENERIC[] = {
    { "PE_Header",                "4D 5A", -1, 0, 0, "*", "DOS Signature" },
};

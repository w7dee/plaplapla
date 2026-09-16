--[[
 * ***********************************************************************************************************************
 * Copyright (c) 2015 OwlGaming Community - All Rights Reserved
 * ***********************************************************************************************************************
 * SECURITY REWRITE - Phase 1
 * التغييرات:
 *  1. على السيرفر: مستويات الصلاحية بتتقرا من كاش داخلي (جدول Lua) مش من elementData.
 *     الكاش بيتملي بس من الكتابات الموثوقة اللي جاية من anticheat -> مستحيل الكلاينت يلوثه.
 *     fallback على elementData لو العنصر لسه مش في الكاش (توافق كامل مع الكود القديم).
 *  2. إصلاح باج قديم: `not getElementType(p) == "player"` كانت دايمًا false
 *     يعني فحص نوع العنصر ما كانش شغال خالص -> كان ممكن تمرير عربية/أوبجكت كـ "لاعب".
 *  3. أوبتمايزيشن: قراءة من جدول Lua بدل getElementData في أكتر من 20 مكان
 *     بتتنده آلاف المرات في الدقيقة (نيم تاجز، سكوربورد، شات...).
 *  4. إضافة getAdminLevel() اللي كانت متصدّرة في meta.xml ومش معرّفة أصلًا.
 * ***********************************************************************************************************************
]]

local SERVER = (triggerClientEvent ~= nil)

-- internal affairs
local internalAffairs = {
}

-- =====================================================================
-- طبقة قراءة المستويات
-- =====================================================================

local STAFF_KEYS = {
	["admin_level"]     = true,
	["supporter_level"] = true,
	["vct_level"]       = true,
	["scripter_level"]  = true,
	["mapper_level"]    = true,
	["fmt_level"]       = true,
	["duty_admin"]      = true,
	["duty_supporter"]  = true,
	["hasVctAdmin"]     = true,
}

local cache = {}   -- [element] = { [key] = value }  (سيرفر فقط)

if SERVER then
	addEvent("anticheat:onTrustedDataSet", false)
	addEventHandler("anticheat:onTrustedDataSet", root,
		function(index, value)
			if not STAFF_KEYS[index] then return end
			if not isElement(source) then return end
			local t = cache[source]
			if not t then
				t = {}
				cache[source] = t
			end
			t[index] = value
		end
	)

	local function dropCache()
		cache[source] = nil
	end
	addEventHandler("onPlayerQuit", root, dropCache)
	addEventHandler("onElementDestroy", root, dropCache)
end

-- فحص صحيح لعنصر اللاعب (الإصدار القديم كان مكسور)
local function isValidPlayer(player)
	return player ~= nil
		and isElement(player)
		and getElementType(player) == "player"
end

-- القراءة الموحّدة
local function getLevel(player, key)
	if not isValidPlayer(player) then return 0 end
	if SERVER then
		local t = cache[player]
		if t and t[key] ~= nil then
			return tonumber(t[key]) or 0
		end
	end
	return tonumber(getElementData(player, key)) or 0
end

-- تُستخدم من الأنظمة التانية لو احتاجت تقرا المستوى مباشرة
function getAdminLevel(player)
	return getLevel(player, "admin_level")
end

function getStaffLevel(player, key)
	if not STAFF_KEYS[key] then return 0 end
	return getLevel(player, key)
end

-- =====================================================================
-- الأدمن
-- =====================================================================

function isPlayerHeadAdmin(player)
	return getLevel(player, "admin_level") >= 5
end

function isPlayerLeadAdmin(player)
	return getLevel(player, "admin_level") >= 4
end

function isPlayerSeniorAdmin(player)
	return getLevel(player, "admin_level") >= 3
end

function isPlayerAdmin(player)
	return getLevel(player, "admin_level") >= 2
end

function isPlayerTrialAdmin(player, duty_required)
	local adminLevel = getLevel(player, "admin_level")
	if adminLevel < 1 then return false end
	if duty_required then
		return getLevel(player, "duty_admin") == 1
	end
	return true
end

-- =====================================================================
-- السبورت
-- =====================================================================

function isPlayerSupporter(player)
	return getLevel(player, "supporter_level") >= 1
end

function isPlayerSupportManager(player)
	return getLevel(player, "supporter_level") >= 2
end

-- =====================================================================
-- السكريبترز
-- =====================================================================

function isPlayerTester(player)
	return getLevel(player, "scripter_level") >= 1
end

function isPlayerScripter(player)
	return getLevel(player, "scripter_level") >= 2
end

function isPlayerLeadScripter(player)
	return getLevel(player, "scripter_level") >= 3
end

function getScripterLevel(player)
	return getLevel(player, "scripter_level")
end

-- =====================================================================
-- VCT
-- =====================================================================

function isPlayerVehicleConsultant(player)
	if not isValidPlayer(player) then return false end
	if getLevel(player, "hasVctAdmin") > 0 then
		return true
	end
	return getLevel(player, "vct_level") >= 2
end

function isPlayerVCTMember(player)
	return getLevel(player, "vct_level") >= 1
end

-- =====================================================================
-- Mapping Team
-- =====================================================================

function isPlayerMappingTeamLeader(player)
	return getLevel(player, "mapper_level") >= 2
end

function isPlayerMappingTeamMember(player)
	return getLevel(player, "mapper_level") >= 1
end

-- =====================================================================
-- FMT
-- =====================================================================

function isPlayerFMTMember(player)
	return getLevel(player, "fmt_level") >= 1
end

function isPlayerFMTLeader(player)
	return getLevel(player, "fmt_level") >= 2
end

-- =====================================================================
-- عام
-- =====================================================================

function isPlayerStaff(player)
	if not isValidPlayer(player) then return false end
	return isPlayerTrialAdmin(player)
		or isPlayerSupporter(player)
		or isPlayerScripter(player)
		or isPlayerVCTMember(player)
		or isPlayerMappingTeamMember(player)
		or isPlayerFMTMember(player)
end

function getAdminGroups() -- this is used in c_adminstats to correspond levels to forum usergroups
	return { SUPPORTER, TRIALADMIN, ADMIN, SENIORADMIN, LEADADMIN, HEADADMIN }
end

-- internal affairs
function isPlayerIA(player)
	return false
end

adminTitles = {
	[1] = "Trial Admin",
	[2] = "Admin",
	[3] = "Senior Admin",
	[4] = "Lead Admin",
	[5] = "Head Admin",
	[10] = "Scripter",
}

function getAdminTitles()
	return adminTitles
end

function getSupporterNumber()
	return SUPPORTER
end

function getAuxiliaryStaffNumbers()
	return table.concat(AUXILIARY_GROUPS, ",")
end

function getAdminStaffNumbers()
	return table.concat(ADMIN_GROUPS, ",")
end

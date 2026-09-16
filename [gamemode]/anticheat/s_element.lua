--[[
 * ***********************************************************************************************************************
 * Copyright (c) 2015 OwlGaming Community - All Rights Reserved
 * ***********************************************************************************************************************
 * SECURITY REWRITE - Phase 1
 * التغييرات:
 *  1. حماية الـ elementData بقت في جدول Lua داخلي بدل elementData نفسها
 *     -> الكلاينت مستحيل يوصلها، + تقليل عدد كتابات elementData من 3 لـ 1 لكل عملية (أوبتمايزيشن)
 *  2. "trusted write" counter: أي كتابة جاية من السيرفر عبر الـ API دي = مسموحة،
 *     أي كتابة تانية على مفتاح محمي = ترجيع + لوج + بان. ده بيقفل ثغرة
 *     saveClientAccountSettingsOnServer وكل الـ events المفتوحة المشابهة.
 *  3. قائمة مفاتيح محمية موسّعة (admin_level / duty_admin / money ... إلخ)
 *  4. تنظيف الجداول عند الخروج -> منع memory leak
 * ملاحظة توافق: كل الدوال القديمة لسه موجودة بنفس الأسماء والباراميترات.
 * ***********************************************************************************************************************
]]

-- =====================================================================
-- الإعدادات
-- =====================================================================

-- المفاتيح اللي ممنوع على الكلاينت يلمسها نهائيًا
local DEFAULT_PROTECTED = {
	-- الحساب والهوية
	"account:id", "account:username", "account:email", "account:loggedin",
	"account:forumid", "dbid", "legitnamechange", "loggedin", "playerid",
	-- الصلاحيات (أهم حاجة)
	"admin_level", "supporter_level", "vct_level", "scripter_level",
	"mapper_level", "fmt_level", "forum_perms", "hiddenadmin",
	"duty_admin", "duty_supporter", "duty", "adminduty", "supervising",
	"supervisorBchat",
	-- الفلوس والممتلكات
	"money", "bankmoney", "credits", "punishment:points", "punishment:date",
	-- الفاكشن والوظيفة
	"faction", "factionrank", "factionleader", "job",
	-- حالة اللاعب
	"muted", "frozen", "godmode", "restrain", "restrainedBy", "restrainedObj",
	"jailed", "arrested", "loginattempts", "timeinserver",
}

-- مفاتيح مستثناة من الفحص أصلًا (بتتغير من الكلاينت بشكل شرعي وكتير)
local IGNORED_INDEXES = {
	["interiormarker"] = true,
}

local BAN_ON_VIOLATION   = true   -- خليها false لو عايز تراقب الأول من غير بان
local VIOLATION_LOG_FILE = "anticheat_violations.log"

-- =====================================================================
-- الحالة الداخلية (Lua tables - الكلاينت لا يراها إطلاقًا)
-- =====================================================================

local protectedKeys = {}  -- [element] = { [index] = true }
local trustedDepth  = 0   -- > 0 يعني الكتابة الحالية جاية من السيرفر بشكل شرعي
local lastViolation = {}  -- [player] = tick  (منع سبام اللوج/البان)

-- =====================================================================
-- دوال مساعدة
-- =====================================================================

local function logViolation(line)
	local f
	if fileExists(VIOLATION_LOG_FILE) then
		f = fileOpen(VIOLATION_LOG_FILE)
		if f then fileSetPos(f, fileGetSize(f)) end
	else
		f = fileCreate(VIOLATION_LOG_FILE)
	end
	if f then
		fileWrite(f, line .. "\n")
		fileClose(f)
	end
	outputServerLog(line)
end

local function describeElement(el)
	if not isElement(el) then return "invalid" end
	if getElementType(el) == "player" then
		return getPlayerName(el) or "unknown-player"
	end
	return getElementType(el) .. ":" .. tostring(el)
end

-- =====================================================================
-- API الحماية (نفس الأسماء القديمة - متوافقة 100%)
-- =====================================================================

function protectElementData(theElement, index)
	if not isElement(theElement) or type(index) ~= "string" then return false end
	local t = protectedKeys[theElement]
	if not t then
		t = {}
		protectedKeys[theElement] = t
	end
	t[index] = true
	return true
end

function allowElementData(theElement, index)
	if not isElement(theElement) or type(index) ~= "string" then return false end
	local t = protectedKeys[theElement]
	if t then t[index] = nil end
	return true
end

function isElementDataProtected(theElement, index)
	local t = protectedKeys[theElement]
	return (t and t[index]) and true or false
end

-- الكتابة الموثوقة: بتزوّد العدّاد فيعرف الـ handler إن دي كتابة شرعية
function changeProtectedElementDataEx(theElement, index, newvalue, sync, noSyncAtAll)
	if not isElement(theElement) or type(index) ~= "string" then return false end

	-- الحفاظ على السلوك القديم: false -> nil
	if newvalue == false then newvalue = nil end

	trustedDepth = trustedDepth + 1
	local ok
	if noSyncAtAll then
		ok = setElementData(theElement, index, newvalue, false)
	else
		ok = setElementData(theElement, index, newvalue, sync and true or false)
	end
	trustedDepth = trustedDepth - 1

	-- مفتاح موجود في القائمة الافتراضية؟ يبقى يفضل محمي دايمًا
	protectElementData(theElement, index)

	-- إشعار للأنظمة التانية (integration بيستخدمه للكاش)
	triggerEvent("anticheat:onTrustedDataSet", theElement, index, newvalue)

	return ok
end

function changeProtectedElementData(theElement, index, newvalue)
	return changeProtectedElementDataEx(theElement, index, newvalue, false)
end

function setEld(theElement, index, newvalue, sync)
	return changeProtectedElementDataEx(theElement, index, newvalue, (sync == "all"))
end

-- للتوافق مع أي كود قديم بينده عليها (بقت بلا معنى لأن الحماية مش في elementData)
function fetchH()
	return "deprecated"
end

-- تُستخدم من أي ريسورس تاني عايز يحمي مفتاح إضافي
function protectKeys(theElement, keys)
	if type(keys) ~= "table" then return false end
	for i = 1, #keys do
		protectElementData(theElement, keys[i])
	end
	return true
end

-- =====================================================================
-- الحارس: أي تغيير غير موثوق على مفتاح محمي
-- =====================================================================

addEventHandler("onElementDataChange", root,
	function(index, oldValue, newValue)
		-- كتابة شرعية من السيرفر -> اخرج فورًا (أسرع مسار)
		if trustedDepth > 0 then return end
		if not client then return end          -- مفيش لاعب وراها = كود سيرفر
		if IGNORED_INDEXES[index] then return end

		local keys = protectedKeys[source]
		if not keys or not keys[index] then return end

		-- ترجيع القيمة
		trustedDepth = trustedDepth + 1
		setElementData(source, index, oldValue)
		trustedDepth = trustedDepth - 1

		-- منع سبام اللوج/البان
		local now = getTickCount()
		if lastViolation[client] and now - lastViolation[client] < 3000 then return end
		lastViolation[client] = now

		local line = ("[%s] ILLEGAL DATA | by=%s serial=%s ip=%s | victim=%s | index=%s | new=%s | old=%s")
			:format(
				os.date("%Y-%m-%d %H:%M:%S"),
				getPlayerName(client) or "?",
				getPlayerSerial(client) or "?",
				getPlayerIP(client) or "?",
				describeElement(source),
				tostring(index),
				tostring(newValue),
				tostring(oldValue)
			)
		logViolation(line)

		if exports.global and exports.global.sendMessageToAdmins then
			exports.global:sendMessageToAdmins("[AdmWarn] " .. (getPlayerName(client) or "?")
				.. " sent illegal data (" .. tostring(index) .. ")")
		end

		if BAN_ON_VIOLATION then
			exports.bans:ban("[ANTICHEAT]", client, 0, "Illegal element data: " .. tostring(index))
		end
	end
)

-- =====================================================================
-- التطبيق عند الدخول + التنظيف عند الخروج
-- =====================================================================

addEventHandler("onPlayerJoin", root,
	function()
		protectKeys(source, DEFAULT_PROTECTED)
	end
)

-- لو الريسورس اتعمله ريستارت واللاعبين موجودين
addEventHandler("onResourceStart", resourceRoot,
	function()
		for _, p in ipairs(getElementsByType("player")) do
			protectKeys(p, DEFAULT_PROTECTED)
		end
	end
)

local function cleanup()
	protectedKeys[source] = nil
	lastViolation[source] = nil
end
addEventHandler("onPlayerQuit", root, cleanup)
addEventHandler("onElementDestroy", root, cleanup)

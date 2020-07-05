-- Logging
-- Part of Live Simulator: 2, can be used as standalone library
--[[---------------------------------------------------------------------------
-- Copyright (c) 2020 Miku AuahDark
--
-- Permission is hereby granted, free of charge, to any person obtaining a
-- copy of this software and associated documentation files (the "Software"),
-- to deal in the Software without restriction, including without limitation
-- the rights to use, copy, modify, merge, publish, distribute, sublicense,
-- and/or sell copies of the Software, and to permit persons to whom the
-- Software is furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
-- OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
-- FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
-- DEALINGS IN THE SOFTWARE.
--]]---------------------------------------------------------------------------

local love = require("love")
local log = {}

-- Modify this variable to anything you want
local ENVIRONMENT_VARIABLE = "NLOG_LOGLEVEL"

-- loglevel
-- 0 = no log message
-- 1 = error
-- 2 = warn (default)
-- 3 = info
-- 4 = debug
local level = tonumber(os.getenv(ENVIRONMENT_VARIABLE))
if not(level) or (level < 0 or level > 4) then
	if love.filesystem then
		level = tonumber((love.filesystem.read(ENVIRONMENT_VARIABLE)))
		if not(level) or (level < 0 or level > 4) then
			level = 2
		end
	else
		level = 2
	end
end

local noop = function () end

-- Default implementation
local function infoImpl(_, tag, text)
	io.stderr:write("I[", tag, "] ", text, "\n")
end
local function warnImpl(_, tag, text)
	io.stderr:write("W[", tag, "] ", text, "\n")
end
local function errorImpl(_, tag, text)
	io.stderr:write("E[", tag, "] ", text, "\n")
end
local function debugImpl(_, tag, text)
	io.stderr:write("D[", tag, "] ", text, "\n")
end

-- Codepath used if ANSI color code is supported
local function setupANSICode()
	local function m(n)
		return string.format("\27[%dm", n)
	end

	function warnImpl(_, tag, text)
		io.stderr:write(m(1), m(33), "W[", tag, "] ", text, m(0), "\n")
	end

	function errorImpl(_, tag, text)
		io.stderr:write(m(31), "E[", tag, "] ", text, m(0), "\n")
	end

	function debugImpl(_, tag, text)
		io.stderr:write(m(1), m(37), "D[", tag, "] ", text, m(0), "\n")
	end
end

if love._os == "Windows" then
	-- Windows can have many options depending on Windows version
	-- * if "ANSICON" environment variable is present, then ANSI color code is used
	-- * if it's possible to set VT100 mode to console (Windows 10 Anniv+), then ANSI color code is used
	-- * otherwise, use Console API for setting color (Windows 10 RTM or older)
	if os.getenv("ANSICON") then
		setupANSICode()
	else
		local hasFFI, ffi = pcall(require, "ffi")
		if hasFFI then
			local bit = require("bit")
			local Kernel32 = ffi.C -- cache namespace
			ffi.cdef [[
				// coord structure
				typedef struct logging_Coord {
					int16_t x, y;
				} logging_Coord;
				// small rect structure
				typedef struct logging_SmallRect {
					int16_t l, t, r, b;
				} logging_SmallRect;
				// CSBI structure
				typedef struct logging_CSBI {
					logging_Coord csbiSize;
					logging_Coord cursorPos;
					int16_t attributes;
					logging_SmallRect windowRect;
					logging_Coord maxWindowSize;
				} logging_CSBI;
				void * __stdcall GetStdHandle(uint32_t );
				int SetConsoleMode(void *, uint32_t );
				int GetConsoleMode(void *, uint32_t *);
				int __stdcall GetConsoleScreenBufferInfo(void *, logging_CSBI *);
				int __stdcall SetConsoleTextAttribute(void *, int16_t );
			]]
			local stderr = Kernel32.GetStdHandle(-12)

			-- Try to use VT100 processing if it's available
			-- Reference: https://bugs.php.net/bug.php?id=72768
			local cmode = ffi.new("uint32_t[1]")
			Kernel32.GetConsoleMode(stderr, cmode);
			-- Try to enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x4)
			if Kernel32.SetConsoleMode(stderr, bit.bor(cmode[0], 4)) > 0 then
				-- ENABLE_VIRTUAL_TERMINAL_PROCESSING is supported. Use ANSI color codes
				setupANSICode()
			else
				-- ENABLE_VIRTUAL_TERMINAL_PROCESSING is not supported. Fallback to Console APIs
				local csbi = ffi.new("logging_CSBI[1]")
				local function pushMode(mode)
					Kernel32.GetConsoleScreenBufferInfo(stderr, csbi)
					local m = csbi[0].attributes
					Kernel32.SetConsoleTextAttribute(stderr, mode)
					return m
				end
				local function popMode(mode)
					Kernel32.SetConsoleTextAttribute(stderr, mode)
					ffi.fill(csbi[0], ffi.sizeof("logging_CSBI"), 0)
				end

				function warnImpl(_, tag, text)
					local m = pushMode(0x0004+0x0002+0x0008) -- bright yellow
					io.stderr:write("W[", tag, "] ", text, "\n")
					io.stderr:flush()
					popMode(m)
				end

				function errorImpl(_, tag, text)
					local m = pushMode(0x0004) -- red
					io.stderr:write("E[", tag, "] ", text, "\n")
					io.stderr:flush()
					popMode(m)
				end

				function debugImpl(_, tag, text)
					local m = pushMode(0x0004+0x0002+0x0001+0x0008) -- bright white
					io.stderr:write("D[", tag, "] ", text, "\n")
					io.stderr:flush()
					popMode(m)
				end
			end
		end
	end
elseif love._os == "Linux" or love._os == "OS X" then
	-- Well does macOS support this?
	setupANSICode()
elseif love._os == "Android" then
	local hasFFI, ffi = pcall(require, "ffi")

	if hasFFI then
		-- Use native Android logging library
		local androidLog = ffi.load("log")

		ffi.cdef[[
		enum AndroidLogPriority {
			unknown,
			default,
			verbose,
			debug,
			info,
			warning, warn = 6,
			error,
			fatal,
			silent
		};

		int __android_log_write(enum AndroidLogPriority, const char *tag, const char *text);
		]]

		function infoImpl(_, tag, text)
			androidLog.__android_log_write("info", tag, text)
		end

		function warnImpl(_, tag, text)
			androidLog.__android_log_write("warning", tag, text)
		end

		function errorImpl(_, tag, text)
			androidLog.__android_log_write("error", tag, text)
		end

		function debugImpl(_, tag, text)
			androidLog.__android_log_write("debug", tag, text)
		end
	else
		-- Screw this, use print and hope for the best
		function infoImpl(_, tag, text)
			print("I["..tag.."] "..text.."\n")
		end

		function warnImpl(_, tag, text)
			print("W["..tag.."] "..text.."\n")
		end

		function errorImpl(_, tag, text)
			print("E["..tag.."] "..text.."\n")
		end

		function debugImpl(_, tag, text)
			print("D["..tag.."] "..text.."\n")
		end
	end
end

local function atomic(f, ...)
	if love.thread then
		if not(log.mutex) then
			-- Lock
			log.mutex = love.thread.getChannel("logging.lock")
		end
		log.mutex:performAtomic(f, ...)
	end

	return f(...)
end

function log.info (tag, text, ...)
	atomic(infoImpl, tag, string.format(text, ...))
end

if level < 3 then
	log.info = noop
end
log.infof = log.info

function log.warning(tag, text, ...)
	if level >= 4 then
		text = debug.traceback(string.format(text, ...), 2)
	end

	atomic(warnImpl, tag, text)
end

if level < 2 then
	log.warning = noop
end
log.warn = log.warning
log.warningf = log.warning
log.warnf = log.warning

function log.error(tag, text, ...)
	if level >= 4 then
		text = debug.traceback(string.format(text, ...), 2)
	end

	atomic(errorImpl, tag, text)
end

if level < 1 then
	log.error = noop
end
log.errorf = log.error

function log.debug(tag, text, ...)
	atomic(debugImpl, tag, string.format(text, ...))
end

if level < 4 then
	log.debug = noop
end
log.debugf = log.debug

function log.getLevel()
	return level
end

return log

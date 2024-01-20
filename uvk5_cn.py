# Quansheng UV-K5 driver (c) 2023 Jacek Lipkowski <sq5bpf@lipkowski.org>
# Modified for Full Chinese Firmware by hank9999
#
# based on template.py Copyright 2012 Dan Smith <dsmith@danplanet.com>
#
#
# This is a preliminary version of a driver for the UV-K5
# It is based on my reverse engineering effort described here:
# https://github.com/sq5bpf/uvk5-reverse-engineering
#
# Warning: this driver is experimental, it may brick your radio,
# eat your lunch and mess up your configuration.
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import struct
import logging
from typing import Union, List

from chirp import chirp_common, directory, bitwise, memmap, errors, util
from chirp.errors import InvalidValueError
from chirp.settings import RadioSetting, RadioSettingGroup, \
      RadioSettingValueBoolean, RadioSettingValueList, \
      RadioSettingValueInteger, RadioSettingValueString, \
      RadioSettings, RadioSettingValue

LOG = logging.getLogger(__name__)

# Show the obfuscated version of commands. Not needed normally, but
# might be useful for someone who is debugging a similar radio
DEBUG_SHOW_OBFUSCATED_COMMANDS = False

# Show the memory being written/received. Not needed normally, because
# this is the same information as in the packet hexdumps, but
# might be useful for someone debugging some obscure memory issue
DEBUG_SHOW_MEMORY_ACTIONS = False

MEM_FORMAT = """
#seekto 0x0000;
struct {
  ul32 freq;
  ul32 offset;
  u8 rxcode;
  u8 txcode;

  u8 unknown1:2,
  txcodeflag:2,
  unknown2:2,
  rxcodeflag:2;

  //u8 flags1;
  u8 flags1_unknown7:1,
  flags1_unknown6:1,
  flags1_unknown5:1,
  enable_am:1,
  flags1_unknown3:1,
  is_in_scanlist:1,
  shift:2;

  //u8 flags2;
  u8 flags2_unknown7:1,
  flags2_unknown6:1,
  flags2_unknown5:1,
  bclo:1,
  txpower:2,
  bandwidth:1,
  freq_reverse:1;

  //u8 dtmf_flags;
  u8 dtmf_flags_unknown7:1,
  dtmf_flags_unknown6:1,
  dtmf_flags_unknown5:1,
  dtmf_flags_unknown4:1,
  dtmf_flags_unknown3:1,
  dtmf_pttid:2,
  dtmf_decode:1;


  u8 step;
  u8 scrambler;
} channel[214];

#seekto 0xd60;
struct {
u8 is_scanlist1:1,
is_scanlist2:1,
unknown1:1,
unknown2:1,
is_free:1,
band:3;
} channel_attributes[200];

#seekto 0xe40;
ul16 fmfreq[20];

#seekto 0xe70;
u8 call_channel;
u8 squelch;
u8 max_talk_time;
u8 noaa_autoscan;
u8 key_lock;
u8 vox_switch;
u8 vox_level;
u8 mic_gain;
u8 unknown3;
u8 channel_display_mode;
u8 crossband;
u8 battery_save;
u8 dual_watch;
u8 backlight_auto_mode;
u8 tail_note_elimination;
u8 vfo_open;

#seekto 0xe90;
u8 beep_control;

#seekto 0xe95;
u8 scan_resume_mode;
u8 auto_keypad_lock;
u8 power_on_dispmode;
u8 password[4];

#seekto 0xea0;
u8 keypad_tone;
u8 language;

#seekto 0xea8;
u8 alarm_mode;
u8 reminding_of_end_talk;
u8 repeater_tail_elimination;

#seekto 0xeb0;
char logo_line1[16];
char logo_line2[16];

#seekto 0xed0;
struct {
u8 side_tone;
char separate_code;
char group_call_code;
u8 decode_response;
u8 auto_reset_time;
u8 preload_time;
u8 first_code_persist_time;
u8 hash_persist_time;
u8 code_persist_time;
u8 code_interval_time;
u8 permit_remote_kill;
} dtmf_settings;

#seekto 0xee0;
struct {
char dtmf_local_code[3];
char unused1[5];
char kill_code[5];
char unused2[3];
char revive_code[5];
char unused3[3];
char dtmf_up_code[16];
char dtmf_down_code[16];
} dtmf_settings_numbers;

#seekto 0xf18;
u8 scanlist_default;
u8 scanlist1_priority_scan;
u8 scanlist1_priority_ch1;
u8 scanlist1_priority_ch2;
u8 scanlist2_priority_scan;
u8 scanlist2_priority_ch1;
u8 scanlist2_priority_ch2;
u8 scanlist_unknown_0xff;


#seekto 0xf40;
u8 lock_flock;

#seekto 0xf42;
u8 lock_killed;

#seekto 0xf46;
u8 lock_enscramble;

#seekto 0xf50;
struct {
char name[16];
} channelname[200];

#seekto 0x1c00;
struct {
char name[8];
char number[3];
char unused_00[5];
} dtmfcontact[16];

#seekto 0x1d00;
struct {
    u8 id[2];
    char name[14];
} mdccontact1[16];

#seekto 0x1ed0;
struct {
struct {
    u8 start;
    u8 mid;
    u8 end;
} low;
struct {
    u8 start;
    u8 mid;
    u8 end;
} medium;
struct {
    u8 start;
    u8 mid;
    u8 end;
} high;
u8 unused_00[7];
} perbandpowersettings[7];

#seekto 0x1f40;
ul16 battery_level[6];

#seekto 0x1f90;
struct {
    u8 id[2];
    char name[14];
} mdccontact2[6];

#seekto 0x1ff8;
u8 mkey_longpress_action;
u8 key1_shortpress_action;
u8 key1_longpress_action;
u8 key2_shortpress_action;
u8 key2_longpress_action;

#seekto 0x1fff;
u8 mdc_num;
"""
# bits that we will save from the channel structure (mostly unknown)
SAVE_MASK_0A = 0b11001100
SAVE_MASK_0B = 0b11101100
SAVE_MASK_0C = 0b11100000
SAVE_MASK_0D = 0b11111000
SAVE_MASK_0E = 0b11110001
SAVE_MASK_0F = 0b11110000

# flags1
FLAGS1_OFFSET_NONE = 0b00
FLAGS1_OFFSET_MINUS = 0b10
FLAGS1_OFFSET_PLUS = 0b01

POWER_HIGH = 0b10
POWER_MEDIUM = 0b01
POWER_LOW = 0b00

# dtmf_flags
PTTID_LIST = ["不发送", "开始上线码", "结束下线码", "开始+结束"]

# power
UVK5_POWER_LEVELS = [chirp_common.PowerLevel("低",  watts=1.50),
                     chirp_common.PowerLevel("中",  watts=3.00),
                     chirp_common.PowerLevel("高", watts=5.00),
                     ]

# scrambler
SCRAMBLER_LIST = ["关闭", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]

# channel display mode
CHANNELDISP_LIST = ["频率", "信道号", "名称", "名称+频率"]
# battery save
BATSAVE_LIST = ["关闭", "1:1", "1:2", "1:3", "1:4"]

# Backlight auto mode
BACKLIGHT_LIST = ["关闭", "5秒", "10秒", "20秒", "1分钟", "2分钟", "4分钟", "开启"]

# Crossband receiving/transmitting
CROSSBAND_LIST = ["关闭", "A段", "B段"]
DUALWATCH_LIST = CROSSBAND_LIST

# steps
STEPS = [2.5, 5.0, 6.25, 10.0, 12.5, 25.0, 8.33]

# ctcss/dcs codes
TMODES = ["", "Tone", "DTCS", "DTCS"]
TONE_NONE = 0
TONE_CTCSS = 1
TONE_DCS = 2
TONE_RDCS = 3


CTCSS_TONES = [
    67.0, 69.3, 71.9, 74.4, 77.0, 79.7, 82.5, 85.4,
    88.5, 91.5, 94.8, 97.4, 100.0, 103.5, 107.2, 110.9,
    114.8, 118.8, 123.0, 127.3, 131.8, 136.5, 141.3, 146.2,
    151.4, 156.7, 159.8, 162.2, 165.5, 167.9, 171.3, 173.8,
    177.3, 179.9, 183.5, 186.2, 189.9, 192.8, 196.6, 199.5,
    203.5, 206.5, 210.7, 218.1, 225.7, 229.1, 233.6, 241.8,
    250.3, 254.1
]

# lifted from ft4.py
DTCS_CODES = [
    23,  25,  26,  31,  32,  36,  43,  47,  51,  53,  54,
    65,  71,  72,  73,  74,  114, 115, 116, 122, 125, 131,
    132, 134, 143, 145, 152, 155, 156, 162, 165, 172, 174,
    205, 212, 223, 225, 226, 243, 244, 245, 246, 251, 252,
    255, 261, 263, 265, 266, 271, 274, 306, 311, 315, 325,
    331, 332, 343, 346, 351, 356, 364, 365, 371, 411, 412,
    413, 423, 431, 432, 445, 446, 452, 454, 455, 462, 464,
    465, 466, 503, 506, 516, 523, 526, 532, 546, 565, 606,
    612, 624, 627, 631, 632, 654, 662, 664, 703, 712, 723,
    731, 732, 734, 743, 754
]

FLOCK_LIST = ["默认+137-174 400-430", "FCC", "CE", "GB", "137-174 400-430", "137-174 400-438", "禁用全部", "解锁全部"]

SCANRESUME_LIST = ["TO: 收到信号5秒后恢复",
                   "CO: 信号消失后恢复",
                   "SE: 收到信号后停止扫描"]

WELCOME_LIST = ["关闭", "图片", "信息"]
KEYPADTONE_LIST = ["关闭", "中文", "English"]
LANGUAGE_LIST = ["中文", "English"]
ALARMMODE_LIST = ["本地", "本地+远端"]
REMENDOFTALK_LIST = ["关闭", "ROGER尾音", "MDC尾音", "MDC首音", "MDC首尾音", "MDC首音+ROGER"]
RTE_LIST = ["关闭", "100ms", "200ms", "300ms", "400ms",
            "500ms", "600ms", "700ms", "800ms", "900ms"]

MEM_SIZE = 0x2000  # size of all memory
PROG_SIZE = 0x1e00  # size of the memory that we will write
MEM_BLOCK = 0x80  # largest block of memory that we can reliably write

# fm radio supported frequencies
FMMIN = 64.0
FMMAX = 108.0

# bands supported by the UV-K5
BANDS = {
        0: [50.0, 76.0],
        1: [108.0, 135.9999],
        2: [136.0, 199.9990],
        3: [200.0, 299.9999],
        4: [350.0, 399.9999],
        5: [400.0, 469.9999],
        6: [470.0, 600.0]
        }

# for radios with modified firmware:
BANDS_NOLIMITS = {
        0: [18.0, 76.0],
        1: [108.0, 135.9999],
        2: [136.0, 199.9990],
        3: [200.0, 299.9999],
        4: [350.0, 399.9999],
        5: [400.0, 469.9999],
        6: [470.0, 1300.0]
        }

SPECIALS = {
        "F1(50M-76M)A": 200,
        "F1(50M-76M)B": 201,
        "F2(108M-136M)A": 202,
        "F2(108M-136M)B": 203,
        "F3(136M-174M)A": 204,
        "F3(136M-174M)B": 205,
        "F4(174M-350M)A": 206,
        "F4(174M-350M)B": 207,
        "F5(350M-400M)A": 208,
        "F5(350M-400M)B": 209,
        "F6(400M-470M)A": 210,
        "F6(400M-470M)B": 211,
        "F7(470M-600M)A": 212,
        "F7(470M-600M)B": 213
        }

VFO_CHANNEL_NAMES = ["F1(50M-76M)A", "F1(50M-76M)B",
                     "F2(108M-136M)A", "F2(108M-136M)B",
                     "F3(136M-174M)A", "F3(136M-174M)B",
                     "F4(174M-350M)A", "F4(174M-350M)B",
                     "F5(350M-400M)A", "F5(350M-400M)B",
                     "F6(400M-470M)A", "F6(400M-470M)B",
                     "F7(470M-600M)A", "F7(470M-600M)B"]

SCANLIST_LIST = ["无", "1", "2", "1+2"]

DTMF_CHARS = "0123456789ABCD*# "
DTMF_CHARS_ID = "0123456789ABCDabcd"
DTMF_CHARS_KILL = "0123456789ABCDabcd"
DTMF_CHARS_UPDOWN = "0123456789ABCDabcd#* "
DTMF_CODE_CHARS = "ABCD*# "
DTMF_DECODE_RESPONSE_LIST = ["关闭", "本地响铃", "回复响应", "响铃+回复"]

KEYACTIONS_LONG_LIST = ["无", "手电筒", "切换发射功率", "监听", "扫描", "声控发射", "FM收音机", "锁定按键", "切换AB信道",
                        "切换信道模式", "切换调制模式", "DTMF解码", "切换宽窄带", "A信道发射", "B信道发射"]

KEYACTIONS_SHORT_LIST = ["无", "手电筒", "切换发射功率", "监听", "扫描", "声控发射", "FM收音机", "锁定按键", "切换AB信道",
                         "切换信道模式", "切换调制模式", "DTMF解码", "切换宽窄带"]

MIC_GAIN_LIST = ["+1.1dB", "+4.0dB", "+8.0dB", "+12.0dB", "+15.1dB"]


def get_gb2312_chinese_characters() -> List[str]:
    characters = []
    for i in range(0xB0, 0xF8):
        for j in range(0xA1, 0xFF):
            try:
                characters.append(bytes([i, j]).decode('gb2312'))
            except Exception:
                pass  # 忽略无法解码的字节对
    return characters


CHINESE_CHARSET = "".join(get_gb2312_chinese_characters())
VALID_CHARACTERS = chirp_common.CHARSET_ASCII + CHINESE_CHARSET


def convert_bytes_to_chinese(data: bytes, fw_version: str) -> str:
    """Convert bytes to a string of chinese characters"""
    return data.decode('gb2312')


def convert_chinese_to_bytes(data: str, fw_version: str) -> bytes:
    return data.encode('gb2312')


class RadioSettingChineseValueString(RadioSettingValueString):

    """A string setting"""

    _fw_version: str

    def __init__(self, minlength, maxlength, current, fw_version: str, autopad=True,
                 charset=chirp_common.CHARSET_ASCII):
        self._fw_version = fw_version
        RadioSettingValueString.__init__(self, minlength, maxlength, current, autopad, charset)

    def set_value(self, value):
        if len(value) < self._minlength or len(convert_chinese_to_bytes(value, self._fw_version)) > self._maxlength:
            raise InvalidValueError("Value must be between %i and %i chars" %
                                    (self._minlength, self._maxlength))
        if self._autopad:
            value = value.ljust(self._maxlength)
        for char in value:
            if char not in self._charset:
                raise InvalidValueError("Value contains invalid " +
                                        "character `%s'" % char)
        RadioSettingValue.set_value(self, value)


def get_mdc_contact_object(mem_obj, index):
    if index <= 16:
        return mem_obj.mdccontact1[index - 1]
    else:
        return mem_obj.mdccontact2[index - 17]


# the communication is obfuscated using this fine mechanism
def xorarr(data: bytes):
    tbl = [22, 108, 20, 230, 46, 145, 13, 64, 33, 53, 213, 64, 19, 3, 233, 128]
    x = b""
    r = 0
    for byte in data:
        x += bytes([byte ^ tbl[r]])
        r = (r+1) % len(tbl)
    return x


# if this crc was used for communication to AND from the radio, then it
# would be a measure to increase reliability.
# but it's only used towards the radio, so it's for further obfuscation
def calculate_crc16_xmodem(data: bytes):
    poly = 0x1021
    crc = 0x0
    for byte in data:
        crc = crc ^ (byte << 8)
        for i in range(8):
            crc = crc << 1
            if (crc & 0x10000):
                crc = (crc ^ poly) & 0xFFFF
    return crc & 0xFFFF


def _send_command(serport, data: bytes):
    """Send a command to UV-K5 radio"""
    LOG.debug("Sending command (unobfuscated) len=0x%4.4x:\n%s" %
              (len(data), util.hexprint(data)))

    crc = calculate_crc16_xmodem(data)
    data2 = data + struct.pack("<H", crc)

    command = struct.pack(">HBB", 0xabcd, len(data), 0) + \
        xorarr(data2) + \
        struct.pack(">H", 0xdcba)
    if DEBUG_SHOW_OBFUSCATED_COMMANDS:
        LOG.debug("Sending command (obfuscated):\n%s" % util.hexprint(command))
    try:
        result = serport.write(command)
    except Exception:
        raise errors.RadioError("Error writing data to radio")
    return result


def _receive_reply(serport):
    header = serport.read(4)
    if len(header) != 4:
        LOG.warning("Header short read: [%s] len=%i" %
                    (util.hexprint(header), len(header)))
        raise errors.RadioError("Header short read")
    if header[0] != 0xAB or header[1] != 0xCD or header[3] != 0x00:
        LOG.warning("Bad response header: %s len=%i" %
                    (util.hexprint(header), len(header)))
        raise errors.RadioError("Bad response header")

    cmd = serport.read(int(header[2]))
    if len(cmd) != int(header[2]):
        LOG.warning("Body short read: [%s] len=%i" %
                    (util.hexprint(cmd), len(cmd)))
        raise errors.RadioError("Command body short read")

    footer = serport.read(4)

    if len(footer) != 4:
        LOG.warning("Footer short read: [%s] len=%i" %
                    (util.hexprint(footer), len(footer)))
        raise errors.RadioError("Footer short read")

    if footer[2] != 0xDC or footer[3] != 0xBA:
        LOG.debug(
                "Reply before bad response footer (obfuscated)"
                "len=0x%4.4x:\n%s" % (len(cmd), util.hexprint(cmd)))
        LOG.warning("Bad response footer: %s len=%i" %
                    (util.hexprint(footer), len(footer)))
        raise errors.RadioError("Bad response footer")

    if DEBUG_SHOW_OBFUSCATED_COMMANDS:
        LOG.debug("Received reply (obfuscated) len=0x%4.4x:\n%s" %
                  (len(cmd), util.hexprint(cmd)))

    cmd2 = xorarr(cmd)

    LOG.debug("Received reply (unobfuscated) len=0x%4.4x:\n%s" %
              (len(cmd2), util.hexprint(cmd2)))

    return cmd2


def _getstring(data: bytes, begin, maxlen):
    tmplen = min(maxlen+1, len(data))
    s = [data[i] for i in range(begin, tmplen)]
    for key, val in enumerate(s):
        if val < ord(' ') or val > ord('~'):
            break
    return ''.join(chr(x) for x in s[0:key])


def _sayhello(serport):
    hellopacket = b"\x14\x05\x04\x00\x6a\x39\x57\x64"

    tries = 5
    while True:
        LOG.debug("Sending hello packet")
        _send_command(serport, hellopacket)
        o = _receive_reply(serport)
        if (o):
            break
        tries -= 1
        if tries == 0:
            LOG.warning("Failed to initialise radio")
            raise errors.RadioError("Failed to initialize radio")
    firmware = _getstring(o, 4, 16)
    LOG.info("Found firmware: %s" % firmware)
    return firmware


def _readmem(serport, offset, length):
    LOG.debug("Sending readmem offset=0x%4.4x len=0x%4.4x" % (offset, length))

    readmem = b"\x1b\x05\x08\x00" + \
        struct.pack("<HBB", offset, length, 0) + \
        b"\x6a\x39\x57\x64"
    _send_command(serport, readmem)
    o = _receive_reply(serport)
    if DEBUG_SHOW_MEMORY_ACTIONS:
        LOG.debug("readmem Received data len=0x%4.4x:\n%s" %
                  (len(o), util.hexprint(o)))
    return o[8:]


def _read_extra_mem(serport, offset: int, length: int, extra: int):
    extra_bytes = struct.pack("<H", extra)
    LOG.debug(
        "Sending read_extra_mem offset=0x%4.4x len=0x%4.4x extra=0x%4.4x" % (offset, length, extra))

    readmem = b"\x2b\x05\x08\x00" + \
              struct.pack("<HBB", offset, length, 0) + \
              b"\x6a\x39\x57\x64" + \
              extra_bytes
    _send_command(serport, readmem)
    o = _receive_reply(serport)
    if DEBUG_SHOW_MEMORY_ACTIONS:
        LOG.debug("read_extra_mem Received data len=0x%4.4x:\n%s" %
                  (len(o), util.hexprint(o)))
    return o[8:]


def _write_extra_mem(serport, offset: int, extra: int, data):
    extra_bytes = struct.pack("<H", extra)
    length = len(data) + len(extra_bytes)
    LOG.debug("Sending write_extra_mem offset=0x%4.4x len=0x%4.4x extra=0x%4.4x" %
              (offset, length, extra))

    if DEBUG_SHOW_MEMORY_ACTIONS:
        LOG.debug("write_extra_mem sent data offset=0x%4.4x len=0x%4.4x add=0x%4.4x:\n%s" %
                  (offset, length, extra, util.hexprint(data)))

    writemem = b"\x38\x05\x1c\x00" + \
        struct.pack("<HBB", offset, length, 0) + \
        b"\x6a\x39\x57\x64" + \
        extra_bytes + data

    _send_command(serport, writemem)
    o = _receive_reply(serport)

    LOG.debug("write_extra_mem Received data: %s len=%i" % (util.hexprint(o), len(o)))

    if (o[0] == 0x1e
            and
            o[4] == (offset & 0xff)
            and
            o[5] == (offset >> 8) & 0xff):
        return True
    else:
        LOG.warning("Bad data from write_extra_mem")
        raise errors.RadioError("Bad response to write_extra_mem")


def _writemem(serport, data, offset):
    LOG.debug("Sending writemem offset=0x%4.4x len=0x%4.4x" %
              (offset, len(data)))

    if DEBUG_SHOW_MEMORY_ACTIONS:
        LOG.debug("writemem sent data offset=0x%4.4x len=0x%4.4x:\n%s" %
                  (offset, len(data), util.hexprint(data)))

    dlen = len(data)
    writemem = b"\x1d\x05" + \
        struct.pack("<BBHBB", dlen+8, 0, offset, dlen, 1) + \
        b"\x6a\x39\x57\x64"+data

    _send_command(serport, writemem)
    o = _receive_reply(serport)

    LOG.debug("writemem Received data: %s len=%i" % (util.hexprint(o), len(o)))

    if (o[0] == 0x1e
            and
            o[4] == (offset & 0xff)
            and
            o[5] == (offset >> 8) & 0xff):
        return True
    else:
        LOG.warning("Bad data from writemem")
        raise errors.RadioError("Bad response to writemem")


def _resetradio(serport):
    resetpacket = b"\xdd\x05\x00\x00"
    _send_command(serport, resetpacket)


def do_download(radio):
    serport = radio.pipe
    serport.timeout = 0.5
    status = chirp_common.Status()
    status.cur = 0
    status.max = MEM_SIZE
    status.msg = "正在从电台下载数据"
    radio.status_fn(status)

    eeprom = b""
    f = _sayhello(serport)
    if f:
        radio.FIRMWARE_VERSION = f
    else:
        raise errors.RadioError('无法检测固件版本')

    addr = 0
    while addr < MEM_SIZE:
        o = _readmem(serport, addr, MEM_BLOCK)
        status.cur = addr
        radio.status_fn(status)

        if o and len(o) == MEM_BLOCK:
            eeprom += o
            addr += MEM_BLOCK
        else:
            raise errors.RadioError("信道未完全下载")
    status.cur = addr
    radio.status_fn(status)
    return memmap.MemoryMapBytes(eeprom)


def do_extra_download(radio):
    serport = radio.pipe
    serport.timeout = 0.5
    status = chirp_common.Status()
    status.cur = 0
    status.max = 3
    status.msg = "正在从电台下载扩容部分数据"
    radio.status_fn(status)

    f = _sayhello(serport)
    if f:
        radio.FIRMWARE_VERSION = f
    else:
        raise errors.RadioError('无法检测固件版本')

    if radio.FIRMWARE_VERSION.endswith('K') or radio.FIRMWARE_VERSION.endswith('H'):
        welcome_len = _read_extra_mem(serport, 0x01, 0x02, 0x2024)
        status.cur = 1
        radio.status_fn(status)
        welcome_len1, welcome_len2 = welcome_len
        if welcome_len1 > 18:
            welcome_len1 = 18
        if welcome_len2 > 18:
            welcome_len2 = 18
        welcome_text_1 = _read_extra_mem(serport, 0x01, welcome_len1, 0x2000)
        status.cur = 2
        radio.status_fn(status)
        welcome_text_2 = _read_extra_mem(serport, 0x01, welcome_len2, 0x2012)
        status.cur = 3
        radio.status_fn(status)
        return [welcome_text_1, welcome_text_2]
    else:
        status.cur = 3
        radio.status_fn(status)
        return [b'', b'']


def do_upload(radio):
    serport = radio.pipe
    serport.timeout = 0.5
    status = chirp_common.Status()
    status.cur = 0
    status.max = PROG_SIZE + 0x70
    status.msg = "正在向电台上传数据"
    radio.status_fn(status)

    f = _sayhello(serport)
    if f:
        radio.FIRMWARE_VERSION = f
    else:
        return False

    addr = 0
    while addr < PROG_SIZE:
        o = radio.get_mmap()[addr:addr+MEM_BLOCK]
        _writemem(serport, o, addr)
        status.cur = addr
        radio.status_fn(status)
        if o:
            addr += MEM_BLOCK
        else:
            raise errors.RadioError("信道未完全上传")
    status.cur = addr
    radio.status_fn(status)

    o = radio.get_mmap()[0x1F90:0x2000]
    _writemem(serport, o, 0x1F90)
    status.cur = PROG_SIZE + 0x70
    radio.status_fn(status)

    status.msg = "上传数据完成"

    return True


def do_extra_upload(radio):
    serport = radio.pipe
    serport.timeout = 0.5
    status = chirp_common.Status()
    status.cur = 0
    status.max = 3
    status.msg = "正在向电台上传扩容部分数据"
    radio.status_fn(status)

    f = _sayhello(serport)
    if f:
        radio.FIRMWARE_VERSION = f
    else:
        return False

    if radio.FIRMWARE_VERSION.endswith('K') or radio.FIRMWARE_VERSION.endswith('H'):
        welcome_logo = radio.get_welcome_logo()
        _write_extra_mem(serport, 0x01, 0x2024, bytes([len(x) for x in welcome_logo]))
        status.cur += 1
        radio.status_fn(status)
        _write_extra_mem(serport, 0x01, 0x2000, b'\x00' * 18)
        _write_extra_mem(serport, 0x01, 0x2000, welcome_logo[0])
        status.cur += 1
        radio.status_fn(status)
        _write_extra_mem(serport, 0x01, 0x2012, b'\x00' * 18)
        _write_extra_mem(serport, 0x01, 0x2012, welcome_logo[1])
        status.cur += 1
        radio.status_fn(status)
    else:
        status.cur += 3
        radio.status_fn(status)
    status.msg = "扩容部分数据上传完成"

    return True


def _find_band(nolimits, hz):
    mhz = hz/1000000.0
    if nolimits:
        B = BANDS_NOLIMITS
    else:
        B = BANDS

    # currently the hacked firmware sets band=1 below 50 MHz
    if nolimits and mhz < 50.0:
        return 1

    for a in B:
        if mhz >= B[a][0] and mhz <= B[a][1]:
            return a
    return False


@directory.register
class UVK5Radio(chirp_common.CloneModeRadio):
    """Quansheng UV-K5"""
    VENDOR = "Quansheng"
    MODEL = "UV-K5 (cn)"
    BAUD_RATE = 38400
    NEEDS_COMPAT_SERIAL = False
    FIRMWARE_VERSION = ""
    _expanded_limits = False

    def __init__(self, pipe):
          super().__init__(pipe)
          self._welcome_logo = [b'', b'']

    def get_prompts(x=None):
        rp = chirp_common.RadioPrompts()
        rp.experimental = (
            '这是用于 Quansheng UV-K5 的实验性驱动。它可能会损坏您的电台，甚至更糟。请自行承担风险。\n'
            '\n' 
            '在尝试进行任何更改之前，请使用 CHIRP 从电台中下载信道镜像并保存下来。这稍后可以用于恢复原始设置。\n'
            '\n'
            '一些细节尚未实现')
        rp.pre_download = (
            "1. 打开电台。\n"
            "2. 将写频线连接到麦克风/扬声器接口。\n"
            "3. 确保连接牢固。\n"
            "4. 点击确定 从设备下载镜像。\n"
            "\n"
            "如果在写频线已经连接的情况下打开电台，可能无法正常使用\n"
        )
        rp.pre_upload = (
            "1. 打开电台。\n"
            "2. 将写频线连接到麦克风/扬声器接口。\n"
            "3. 确保连接牢固。\n"
            "4. 点击确定 将镜像上传到设备。\n"
            "\n"
            "如果在写频线已经连接的情况下打开电台，可能无法正常使用\n"
        )
        return rp

    # Return information about this radio's features, including
    # how many memories it has, what bands it supports, etc
    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_bank = False
        rf.valid_dtcs_codes = DTCS_CODES
        rf.has_rx_dtcs = True
        rf.has_ctone = True
        rf.has_settings = True
        rf.has_comment = False
        rf.valid_name_length = 10
        rf.valid_power_levels = UVK5_POWER_LEVELS
        rf.valid_special_chans = list(SPECIALS.keys())
        rf.valid_duplexes = ["", "-", "+", "off"]

        # hack so we can input any frequency,
        # the 0.1 and 0.01 steps don't work unfortunately
        rf.valid_tuning_steps = [0.01, 0.1, 1.0] + STEPS

        rf.valid_tmodes = ["", "Tone", "TSQL", "DTCS", "Cross"]
        rf.valid_cross_modes = ["Tone->Tone", "Tone->DTCS", "DTCS->Tone",
                                "->Tone", "->DTCS", "DTCS->", "DTCS->DTCS"]

        rf.valid_characters = VALID_CHARACTERS
        rf.valid_modes = ["FM", "NFM", "AM", "NAM"]

        rf.valid_skips = [""]

        # This radio supports memories 1-200, 201-214 are the VFO memories
        rf.memory_bounds = (1, 200)

        rf.valid_bands = []
        for a in BANDS_NOLIMITS:
            rf.valid_bands.append(
                    (int(BANDS_NOLIMITS[a][0]*1000000),
                     int(BANDS_NOLIMITS[a][1]*1000000)))
        return rf

    # Do a download of the radio from the serial port
    def sync_in(self):
        self._mmap = do_download(self)
        self._welcome_logo = do_extra_download(self)
        self.process_mmap()

    # Do an upload of the radio to the serial port
    def sync_out(self):
        do_upload(self)
        do_extra_upload(self)
        _resetradio(self.pipe)

    # Convert the raw byte array into a memory object structure
    def process_mmap(self):
        self._memobj = bitwise.parse(MEM_FORMAT, self._mmap)

    # Return a raw representation of the memory object, which
    # is very helpful for development
    def get_raw_memory(self, number):
        return repr(self._memobj.channel[number-1])

    def get_welcome_logo(self):
        return self._welcome_logo

    def validate_memory(self, mem):
        msgs = super().validate_memory(mem)

        if mem.duplex == 'off':
            return msgs

        # find tx frequency
        if mem.duplex == '-':
            txfreq = mem.freq - mem.offset
        elif mem.duplex == '+':
            txfreq = mem.freq + mem.offset
        else:
            txfreq = mem.freq

        # find band
        band = _find_band(self._expanded_limits, txfreq)
        if band is False:
            msg = "Transmit frequency %.4f MHz is not supported by this radio"\
                   % (txfreq/1000000.0)
            msgs.append(chirp_common.ValidationError(msg))

        band = _find_band(self._expanded_limits, mem.freq)
        if band is False:
            msg = "The frequency %.4f MHz is not supported by this radio" \
                   % (mem.freq/1000000.0)
            msgs.append(chirp_common.ValidationError(msg))

        return msgs

    def _set_tone(self, mem, _mem):
        ((txmode, txtone, txpol),
         (rxmode, rxtone, rxpol)) = chirp_common.split_tone_encode(mem)

        if txmode == "Tone":
            txtoval = CTCSS_TONES.index(txtone)
            txmoval = 0b01
        elif txmode == "DTCS":
            txmoval = txpol == "R" and 0b11 or 0b10
            txtoval = DTCS_CODES.index(txtone)
        else:
            txmoval = 0
            txtoval = 0

        if rxmode == "Tone":
            rxtoval = CTCSS_TONES.index(rxtone)
            rxmoval = 0b01
        elif rxmode == "DTCS":
            rxmoval = rxpol == "R" and 0b11 or 0b10
            rxtoval = DTCS_CODES.index(rxtone)
        else:
            rxmoval = 0
            rxtoval = 0

        _mem.rxcodeflag = rxmoval
        _mem.txcodeflag = txmoval
        _mem.unknown1 = 0
        _mem.unknown2 = 0
        _mem.rxcode = rxtoval
        _mem.txcode = txtoval

    def _get_tone(self, mem, _mem):
        rxtype = _mem.rxcodeflag
        txtype = _mem.txcodeflag
        rx_tmode = TMODES[rxtype]
        tx_tmode = TMODES[txtype]

        rx_tone = tx_tone = None

        if tx_tmode == "Tone":
            if _mem.txcode < len(CTCSS_TONES):
                tx_tone = CTCSS_TONES[_mem.txcode]
            else:
                tx_tone = 0
                tx_tmode = ""
        elif tx_tmode == "DTCS":
            if _mem.txcode < len(DTCS_CODES):
                tx_tone = DTCS_CODES[_mem.txcode]
            else:
                tx_tone = 0
                tx_tmode = ""

        if rx_tmode == "Tone":
            if _mem.rxcode < len(CTCSS_TONES):
                rx_tone = CTCSS_TONES[_mem.rxcode]
            else:
                rx_tone = 0
                rx_tmode = ""
        elif rx_tmode == "DTCS":
            if _mem.rxcode < len(DTCS_CODES):
                rx_tone = DTCS_CODES[_mem.rxcode]
            else:
                rx_tone = 0
                rx_tmode = ""

        tx_pol = txtype == 0x03 and "R" or "N"
        rx_pol = rxtype == 0x03 and "R" or "N"

        chirp_common.split_tone_decode(mem, (tx_tmode, tx_tone, tx_pol),
                                       (rx_tmode, rx_tone, rx_pol))

    # Extract a high-level memory object from the low-level memory map
    # This is called to populate a memory in the UI
    def get_memory(self, number2):

        mem = chirp_common.Memory()

        if isinstance(number2, str):
            number = SPECIALS[number2]
            mem.extd_number = number2
        else:
            number = number2 - 1

        mem.number = number + 1

        _mem = self._memobj.channel[number]

        tmpcomment = ""

        is_empty = False
        # We'll consider any blank (i.e. 0 MHz frequency) to be empty
        if (_mem.freq == 0xffffffff) or (_mem.freq == 0):
            is_empty = True

        tmpscn = SCANLIST_LIST[0]

        # We'll also look at the channel attributes if a memory has them
        if number < 200:
            _mem3 = self._memobj.channel_attributes[number]
            # free memory bit
            if _mem3.is_free > 0:
                is_empty = True
            # scanlists
            if _mem3.is_scanlist1 > 0 and _mem3.is_scanlist2 > 0:
                tmpscn = SCANLIST_LIST[3]  # "1+2"
            elif _mem3.is_scanlist1 > 0:
                tmpscn = SCANLIST_LIST[1]  # "1"
            elif _mem3.is_scanlist2 > 0:
                tmpscn = SCANLIST_LIST[2]  # "2"

        if is_empty:
            mem.empty = True
            # set some sane defaults:
            mem.power = UVK5_POWER_LEVELS[2]
            mem.extra = RadioSettingGroup("Extra", "extra")
            rs = RadioSetting(
                "bclo", "遇忙禁发",
                RadioSettingValueBoolean(False))
            mem.extra.append(rs)
            rs = RadioSetting(
                "frev", "倒频",
                RadioSettingValueBoolean(False))
            mem.extra.append(rs)
            rs = RadioSetting(
                "pttid", "PTTID",
                RadioSettingValueList(PTTID_LIST, PTTID_LIST[0]))
            mem.extra.append(rs)
            rs = RadioSetting(
                "dtmfdecode", "DTMF解码",
                RadioSettingValueBoolean(False))
            mem.extra.append(rs)
            rs = RadioSetting(
                "scrambler", "扰频",
                RadioSettingValueList(SCRAMBLER_LIST, SCRAMBLER_LIST[0]))
            mem.extra.append(rs)

            rs = RadioSetting(
                "scanlists", "扫描列表",
                RadioSettingValueList(SCANLIST_LIST, SCANLIST_LIST[0]))
            mem.extra.append(rs)

            # actually the step and duplex are overwritten by chirp based on
            # bandplan. they are here to document sane defaults for IARU r1
            # mem.tuning_step = 25.0
            # mem.duplex = ""

            return mem

        if number > 199:
            mem.immutable = ["name", "scanlists"]
        else:
            _mem2 = self._memobj.channelname[number]
            raw_bytes = _mem2.get_raw()
            mem.name = convert_bytes_to_chinese(raw_bytes, self.FIRMWARE_VERSION).rstrip()

        # Convert your low-level frequency to Hertz
        mem.freq = int(_mem.freq)*10
        mem.offset = int(_mem.offset)*10

        if (mem.offset == 0):
            mem.duplex = ''
        else:
            if _mem.shift == FLAGS1_OFFSET_MINUS:
                if _mem.freq == _mem.offset:
                    # fake tx disable by setting tx to 0 MHz
                    mem.duplex = 'off'
                    mem.offset = 0
                else:
                    mem.duplex = '-'
            elif _mem.shift == FLAGS1_OFFSET_PLUS:
                mem.duplex = '+'
            else:
                mem.duplex = ''

        # tone data
        self._get_tone(mem, _mem)

        # mode
        if _mem.enable_am > 0:
            if _mem.bandwidth > 0:
                mem.mode = "NAM"
            else:
                mem.mode = "AM"
        else:
            if _mem.bandwidth > 0:
                mem.mode = "NFM"
            else:
                mem.mode = "FM"

        # tuning step
        tstep = _mem.step & 0x7
        if tstep < len(STEPS):
            mem.tuning_step = STEPS[tstep]
        else:
            mem.tuning_step = 2.5

        # power
        if _mem.txpower == POWER_HIGH:
            mem.power = UVK5_POWER_LEVELS[2]
        elif _mem.txpower == POWER_MEDIUM:
            mem.power = UVK5_POWER_LEVELS[1]
        else:
            mem.power = UVK5_POWER_LEVELS[0]

        # We'll consider any blank (i.e. 0 MHz frequency) to be empty
        if (_mem.freq == 0xffffffff) or (_mem.freq == 0):
            mem.empty = True
        else:
            mem.empty = False

        mem.extra = RadioSettingGroup("Extra", "extra")

        # BCLO
        is_bclo = bool(_mem.bclo > 0)
        rs = RadioSetting("bclo", "遇忙禁发", RadioSettingValueBoolean(is_bclo))
        mem.extra.append(rs)
        tmpcomment += "BCLO:"+(is_bclo and "ON" or "off")+" "

        # Frequency reverse - whatever that means, don't see it in the manual
        is_frev = bool(_mem.freq_reverse > 0)
        rs = RadioSetting("frev", "倒频", RadioSettingValueBoolean(is_frev))
        mem.extra.append(rs)
        tmpcomment += "FreqReverse:"+(is_frev and "ON" or "off")+" "

        # PTTID
        pttid = _mem.dtmf_pttid
        rs = RadioSetting("pttid", "PTTID", RadioSettingValueList(
            PTTID_LIST, PTTID_LIST[pttid]))
        mem.extra.append(rs)
        tmpcomment += "PTTid:"+PTTID_LIST[pttid]+" "

        # DTMF DECODE
        is_dtmf = bool(_mem.dtmf_decode > 0)
        rs = RadioSetting("dtmfdecode", "DTMF解码",
                          RadioSettingValueBoolean(is_dtmf))
        mem.extra.append(rs)
        tmpcomment += "DTMFdecode:"+(is_dtmf and "ON" or "off")+" "

        # Scrambler
        if _mem.scrambler & 0x0f < len(SCRAMBLER_LIST):
            enc = _mem.scrambler & 0x0f
        else:
            enc = 0

        rs = RadioSetting("scrambler", "扰频", RadioSettingValueList(
            SCRAMBLER_LIST, SCRAMBLER_LIST[enc]))
        mem.extra.append(rs)
        tmpcomment += "Scrambler:"+SCRAMBLER_LIST[enc]+" "

        rs = RadioSetting("scanlists", "扫描列表", RadioSettingValueList(
            SCANLIST_LIST, tmpscn))
        mem.extra.append(rs)

        return mem

    def set_settings(self, settings):
        _mem = self._memobj
        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue

            # basic settings

            # call channel
            if element.get_name() == "call_channel":
                _mem.call_channel = int(element.value)-1

            # squelch
            if element.get_name() == "squelch":
                _mem.squelch = int(element.value)
            # TOT
            if element.get_name() == "tot":
                _mem.max_talk_time = int(element.value)

            # NOAA autoscan
            if element.get_name() == "noaa_autoscan":
                _mem.noaa_autoscan = element.value and 1 or 0

            # VOX switch
            if element.get_name() == "vox_switch":
                _mem.vox_switch = element.value and 1 or 0

            # vox level
            if element.get_name() == "vox_level":
                _mem.vox_level = int(element.value)-1

            # mic gain
            if element.get_name() == "mic_gain":
                if str(element.value) in MIC_GAIN_LIST:
                    _mem.mic_gain = int(MIC_GAIN_LIST.index(str(element.value)))
                else:
                    _mem.mic_gain = 2

            # Channel display mode
            if element.get_name() == "channel_display_mode":
                _mem.channel_display_mode = CHANNELDISP_LIST.index(
                    str(element.value))

            # Crossband receiving/transmitting
            if element.get_name() == "crossband":
                _mem.crossband = CROSSBAND_LIST.index(str(element.value))

            # Battery Save
            if element.get_name() == "battery_save":
                _mem.battery_save = BATSAVE_LIST.index(str(element.value))
            # Dual Watch
            if element.get_name() == "dualwatch":
                _mem.dual_watch = DUALWATCH_LIST.index(str(element.value))

            # Backlight auto mode
            if element.get_name() == "backlight_auto_mode":
                _mem.backlight_auto_mode = \
                        BACKLIGHT_LIST.index(str(element.value))

            # Tail tone elimination
            if element.get_name() == "tail_note_elimination":
                _mem.tail_note_elimination = element.value and 1 or 0

            # VFO Open
            if element.get_name() == "vfo_open":
                _mem.vfo_open = element.value and 1 or 0

            # Beep control
            if element.get_name() == "beep_control":
                _mem.beep_control = element.value and 1 or 0

            # Scan resume mode
            if element.get_name() == "scan_resume_mode":
                _mem.scan_resume_mode = SCANRESUME_LIST.index(
                    str(element.value))

            # Keypad lock
            if element.get_name() == "key_lock":
                _mem.key_lock = element.value and 1 or 0

            # Auto keypad lock
            if element.get_name() == "auto_keypad_lock":
                _mem.auto_keypad_lock = element.value and 1 or 0

            # Power on display mode
            if element.get_name() == "welcome_mode":
                _mem.power_on_dispmode = WELCOME_LIST.index(str(element.value))

            # Keypad Tone
            if element.get_name() == "keypad_tone":
                _mem.keypad_tone = KEYPADTONE_LIST.index(str(element.value))

            # Language
            if element.get_name() == "language":
                _mem.language = LANGUAGE_LIST.index(str(element.value))

            # Alarm mode
            if element.get_name() == "alarm_mode":
                _mem.alarm_mode = ALARMMODE_LIST.index(str(element.value))

            # Reminding of end of talk
            if element.get_name() == "reminding_of_end_talk":
                _mem.reminding_of_end_talk = REMENDOFTALK_LIST.index(
                    str(element.value))

            # Repeater tail tone elimination
            if element.get_name() == "repeater_tail_elimination":
                _mem.repeater_tail_elimination = RTE_LIST.index(
                    str(element.value))

            # Logo string 1
            if element.get_name() == "logo1":
                if self.FIRMWARE_VERSION.endswith('K') or self.FIRMWARE_VERSION.endswith('H'):
                    b = convert_chinese_to_bytes(str(element.value), self.FIRMWARE_VERSION)
                    self._welcome_logo[0] = b[0:18]
                else:
                    b = str(element.value).rstrip("\x20\xff\x00") + "\x00" * 12
                    _mem.logo_line1 = b[0:12] + "\x00\xff\xff\xff"

            # Logo string 2
            if element.get_name() == "logo2":
                if self.FIRMWARE_VERSION.endswith('K') or self.FIRMWARE_VERSION.endswith('H'):
                    b = convert_chinese_to_bytes(str(element.value), self.FIRMWARE_VERSION)
                    self._welcome_logo[1] = b[0:18]
                else:
                    b = str(element.value).rstrip("\x20\xff\x00") + "\x00" * 12
                    _mem.logo_line2 = b[0:12] + "\x00\xff\xff\xff"

            # unlock settings

            # FLOCK
            if element.get_name() == "flock":
                _mem.lock_flock = FLOCK_LIST.index(str(element.value))

            # # 350TX
            # if element.get_name() == "tx350":
            #     _mem.lock.tx350 = element.value and 1 or 0
            #
            # # 200TX
            # if element.get_name() == "tx200":
            #     _mem.lock.tx200 = element.value and 1 or 0
            #
            # # 500TX
            # if element.get_name() == "tx500":
            #     _mem.lock.tx500 = element.value and 1 or 0
            #
            # # 350EN
            # if element.get_name() == "en350":
            #     _mem.lock.en350 = element.value and 1 or 0

            # SCREN
            if element.get_name() == "enscramble":
                _mem.lock_enscramble = element.value and 1 or 0

            # KILLED
            if element.get_name() == "killed":
                _mem.lock_killed = element.value and 1 or 0

            # fm radio
            for i in range(1, 21):
                freqname = "FM_" + str(i)
                if element.get_name() == freqname:
                    val = str(element.value).strip()
                    try:
                        val2 = int(float(val)*10)
                    except Exception:
                        val2 = 0xffff

                    if val2 < FMMIN*10 or val2 > FMMAX*10:
                        val2 = 0xffff
#                        raise errors.InvalidValueError(
#                                "FM radio frequency should be a value "
#                                "in the range %.1f - %.1f" % (FMMIN , FMMAX))
                    _mem.fmfreq[i-1] = val2

            # dtmf settings
            if element.get_name() == "dtmf_side_tone":
                _mem.dtmf_settings.side_tone = \
                        element.value and 1 or 0

            if element.get_name() == "dtmf_separate_code":
                _mem.dtmf_settings.separate_code = str(element.value)

            if element.get_name() == "dtmf_group_call_code":
                _mem.dtmf_settings.group_call_code = element.value

            if element.get_name() == "dtmf_decode_response":
                _mem.dtmf_settings.decode_response = \
                        DTMF_DECODE_RESPONSE_LIST.index(str(element.value))

            if element.get_name() == "dtmf_auto_reset_time":
                _mem.dtmf_settings.auto_reset_time = \
                        int(int(element.value)/10)

            if element.get_name() == "dtmf_preload_time":
                _mem.dtmf_settings.preload_time = \
                        int(int(element.value)/10)

            if element.get_name() == "dtmf_first_code_persist_time":
                _mem.dtmf_settings.first_code_persist_time = \
                        int(int(element.value)/10)

            if element.get_name() == "dtmf_hash_persist_time":
                _mem.dtmf_settings.hash_persist_time = \
                        int(int(element.value)/10)

            if element.get_name() == "dtmf_code_persist_time":
                _mem.dtmf_settings.code_persist_time = \
                        int(int(element.value)/10)

            if element.get_name() == "dtmf_code_interval_time":
                _mem.dtmf_settings.code_interval_time = \
                        int(int(element.value)/10)

            if element.get_name() == "dtmf_permit_remote_kill":
                _mem.dtmf_settings.permit_remote_kill = \
                        element.value and 1 or 0

            if element.get_name() == "dtmf_dtmf_local_code":
                k = str(element.value).rstrip("\x20\xff\x00") + "\x00"*3
                _mem.dtmf_settings_numbers.dtmf_local_code = k[0:3]

            if element.get_name() == "dtmf_dtmf_up_code":
                k = str(element.value).strip("\x20\xff\x00") + "\x00"*16
                _mem.dtmf_settings_numbers.dtmf_up_code = k[0:16]

            if element.get_name() == "dtmf_dtmf_down_code":
                k = str(element.value).rstrip("\x20\xff\x00") + "\x00"*16
                _mem.dtmf_settings_numbers.dtmf_down_code = k[0:16]

            if element.get_name() == "dtmf_kill_code":
                k = str(element.value).strip("\x20\xff\x00") + "\x00"*5
                _mem.dtmf_settings_numbers.kill_code = k[0:5]

            if element.get_name() == "dtmf_revive_code":
                k = str(element.value).strip("\x20\xff\x00") + "\x00"*5
                _mem.dtmf_settings_numbers.revive_code = k[0:5]

            # dtmf contacts
            for i in range(1, 17):
                varname = "DTMF_" + str(i)
                if element.get_name() == varname:
                    k = str(element.value).rstrip("\x20\xff\x00") + "\x00"*8
                    _mem.dtmfcontact[i-1].name = k[0:8]

                varnumname = "DTMFNUM_" + str(i)
                if element.get_name() == varnumname:
                    k = str(element.value).rstrip("\x20\xff\x00") + "\xff"*3
                    _mem.dtmfcontact[i-1].number = k[0:3]

            # MDC 联系人
            element_name = element.get_name()
            valid_mdc = 0
            last_valid = 0
            for i in range(1, 23):
                mdc_id = "MDC_ID_" + str(i)
                mdc_name = "MDC_NAME_" + str(i)
                if element_name == mdc_id:
                    k = str(element.value).replace(' ', '').rjust(4, '0')
                    get_mdc_contact_object(_mem, i).id = bytes.fromhex(k)[0:2]

                if element_name == mdc_name:
                    get_mdc_contact_object(_mem, i).name = str(element.value)[0:14]

                mdc_obj = get_mdc_contact_object(_mem, i)
                is_not_empty = mdc_obj.id.get_raw() != b'\x00' * 2 and mdc_obj.name.get_raw() != b'\x20' * 20
                if is_not_empty and (last_valid == i - 1 or last_valid == 0):
                    valid_mdc = i
                    last_valid = i
            _mem.mdc_num = valid_mdc

            # scanlist stuff
            if element.get_name() == "scanlist_default":
                val = (int(element.value) == 2) and 1 or 0
                _mem.scanlist_default = val

            if element.get_name() == "scanlist1_priority_scan":
                _mem.scanlist1_priority_scan = \
                        element.value and 1 or 0

            if element.get_name() == "scanlist2_priority_scan":
                _mem.scanlist2_priority_scan = \
                        element.value and 1 or 0

            if element.get_name() == "scanlist1_priority_ch1" or \
                    element.get_name() == "scanlist1_priority_ch2" or \
                    element.get_name() == "scanlist2_priority_ch1" or \
                    element.get_name() == "scanlist2_priority_ch2":

                val = int(element.value)

                if val > 200 or val < 1:
                    val = 0xff
                else:
                    val -= 1

                if element.get_name() == "scanlist1_priority_ch1":
                    _mem.scanlist1_priority_ch1 = val
                if element.get_name() == "scanlist1_priority_ch2":
                    _mem.scanlist1_priority_ch2 = val
                if element.get_name() == "scanlist2_priority_ch1":
                    _mem.scanlist2_priority_ch1 = val
                if element.get_name() == "scanlist2_priority_ch2":
                    _mem.scanlist2_priority_ch2 = val

            if element.get_name() == "key1_shortpress_action":
                _mem.key1_shortpress_action = KEYACTIONS_SHORT_LIST.index(
                        str(element.value))

            if element.get_name() == "key1_longpress_action":
                _mem.key1_longpress_action = KEYACTIONS_LONG_LIST.index(
                        str(element.value))

            if element.get_name() == "key2_shortpress_action":
                _mem.key2_shortpress_action = KEYACTIONS_SHORT_LIST.index(
                        str(element.value))

            if element.get_name() == "key2_longpress_action":
                _mem.key2_longpress_action = KEYACTIONS_LONG_LIST.index(
                        str(element.value))

            if element.get_name() == "mkey_longpress_action":
                _mem.key2_longpress_action = KEYACTIONS_LONG_LIST.index(
                        str(element.value))

            if element.get_name() == "nolimits":
                LOG.warning("User expanded band limits")
                self._expanded_limits = bool(element.value)

    def get_settings(self):
        _mem = self._memobj
        basic = RadioSettingGroup("basic", "基本设置")
        keya = RadioSettingGroup("keya", "自定义按键")
        dtmf = RadioSettingGroup("dtmf", "DTMF 设置")
        dtmfc = RadioSettingGroup("dtmfc", "DTMF 联系人")
        mdcc = RadioSettingGroup("mdcc", "MDC 联系人")
        scanl = RadioSettingGroup("scn", "扫描列表")
        unlock = RadioSettingGroup("unlock", "解锁设置")
        fmradio = RadioSettingGroup("fmradio", "FM广播")

        roinfo = RadioSettingGroup("roinfo", "设备信息")

        top = RadioSettings(
                basic, keya, dtmf, dtmfc, mdcc, scanl, unlock, fmradio, roinfo)

        # Programmable keys
        tmpval = int(_mem.key1_shortpress_action)
        if tmpval >= len(KEYACTIONS_SHORT_LIST):
            tmpval = 0
        rs = RadioSetting("key1_shortpress_action", "侧键1短按",
                          RadioSettingValueList(
                              KEYACTIONS_SHORT_LIST, KEYACTIONS_SHORT_LIST[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.key1_longpress_action)
        if tmpval >= len(KEYACTIONS_LONG_LIST):
            tmpval = 0
        rs = RadioSetting("key1_longpress_action", "侧键1长按",
                          RadioSettingValueList(
                              KEYACTIONS_LONG_LIST, KEYACTIONS_LONG_LIST[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.key2_shortpress_action)
        if tmpval >= len(KEYACTIONS_SHORT_LIST):
            tmpval = 0
        rs = RadioSetting("key2_shortpress_action", "侧键2短按",
                          RadioSettingValueList(
                              KEYACTIONS_SHORT_LIST, KEYACTIONS_SHORT_LIST[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.key2_longpress_action)
        if tmpval >= len(KEYACTIONS_LONG_LIST):
            tmpval = 0
        rs = RadioSetting("key2_longpress_action", "侧键2长按",
                          RadioSettingValueList(
                              KEYACTIONS_LONG_LIST, KEYACTIONS_LONG_LIST[tmpval]))
        keya.append(rs)

        tmpval = int(_mem.mkey_longpress_action)
        if tmpval >= len(KEYACTIONS_LONG_LIST):
            tmpval = 0
        rs = RadioSetting("mkey_longpress_action", "M键长按",
                          RadioSettingValueList(
                              KEYACTIONS_LONG_LIST, KEYACTIONS_LONG_LIST[tmpval]))
        keya.append(rs)

        # DTMF settings
        tmppr = bool(_mem.dtmf_settings.side_tone > 0)
        rs = RadioSetting(
                "dtmf_side_tone",
                "DTMF 侧音",
                RadioSettingValueBoolean(tmppr))
        dtmf.append(rs)

        tmpval = str(_mem.dtmf_settings.separate_code)
        if tmpval not in DTMF_CODE_CHARS:
            tmpval = '*'
        val = RadioSettingValueString(1, 1, tmpval)
        val.set_charset(DTMF_CODE_CHARS)
        rs = RadioSetting("dtmf_separate_code", "分隔码", val)
        dtmf.append(rs)

        tmpval = str(_mem.dtmf_settings.group_call_code)
        if tmpval not in DTMF_CODE_CHARS:
            tmpval = '#'
        val = RadioSettingValueString(1, 1, tmpval)
        val.set_charset(DTMF_CODE_CHARS)
        rs = RadioSetting("dtmf_group_call_code", "组呼码", val)
        dtmf.append(rs)

        tmpval = _mem.dtmf_settings.decode_response
        if tmpval >= len(DTMF_DECODE_RESPONSE_LIST):
            tmpval = 0
        rs = RadioSetting("dtmf_decode_response", "解码响应",
                          RadioSettingValueList(
                              DTMF_DECODE_RESPONSE_LIST,
                              DTMF_DECODE_RESPONSE_LIST[tmpval]))
        dtmf.append(rs)

        tmpval = _mem.dtmf_settings.auto_reset_time
        if tmpval > 60 or tmpval < 5:
            tmpval = 5
        rs = RadioSetting("dtmf_auto_reset_time",
                          "自动复位时间 (秒)",
                          RadioSettingValueInteger(5, 60, tmpval))
        dtmf.append(rs)

        tmpval = int(_mem.dtmf_settings.preload_time)
        if tmpval > 100 or tmpval < 3:
            tmpval = 30
        tmpval *= 10
        rs = RadioSetting("dtmf_preload_time",
                          "预载波时间 (ms)",
                          RadioSettingValueInteger(30, 1000, tmpval, 10))
        dtmf.append(rs)

        tmpval = int(_mem.dtmf_settings.first_code_persist_time)
        if tmpval > 100 or tmpval < 3:
            tmpval = 30
        tmpval *= 10
        rs = RadioSetting("dtmf_first_code_persist_time",
                          "首码持续时间 (ms)",
                          RadioSettingValueInteger(30, 1000, tmpval, 10))
        dtmf.append(rs)

        tmpval = int(_mem.dtmf_settings.hash_persist_time)
        if tmpval > 100 or tmpval < 3:
            tmpval = 30
        tmpval *= 10
        rs = RadioSetting("dtmf_hash_persist_time",
                          "*/# 码持续时间 (ms)",
                          RadioSettingValueInteger(30, 1000, tmpval, 10))
        dtmf.append(rs)

        tmpval = int(_mem.dtmf_settings.code_persist_time)
        if tmpval > 100 or tmpval < 3:
            tmpval = 30
        tmpval *= 10
        rs = RadioSetting("dtmf_code_persist_time",
                          "单码持续时间 (ms)",
                          RadioSettingValueInteger(30, 1000, tmpval, 10))
        dtmf.append(rs)

        tmpval = int(_mem.dtmf_settings.code_interval_time)
        if tmpval > 100 or tmpval < 3:
            tmpval = 30
        tmpval *= 10
        rs = RadioSetting("dtmf_code_interval_time",
                          "码间间隔时间 (ms)",
                          RadioSettingValueInteger(30, 1000, tmpval, 10))
        dtmf.append(rs)

        tmpval = bool(_mem.dtmf_settings.permit_remote_kill > 0)
        rs = RadioSetting(
                "dtmf_permit_remote_kill",
                "允许遥毙",
                RadioSettingValueBoolean(tmpval))
        dtmf.append(rs)

        tmpval = str(_mem.dtmf_settings_numbers.dtmf_local_code).upper().strip(
                "\x00\xff\x20")
        for i in tmpval:
            if i in DTMF_CHARS_ID:
                continue
            else:
                tmpval = "103"
                break
        val = RadioSettingValueString(3, 3, tmpval)
        val.set_charset(DTMF_CHARS_ID)
        rs = RadioSetting("dtmf_dtmf_local_code",
                          "身份码 (3字符 0-9 ABCD)", val)
        dtmf.append(rs)

        tmpval = str(_mem.dtmf_settings_numbers.dtmf_up_code).upper().strip(
                "\x00\xff\x20")
        for i in tmpval:
            if i in DTMF_CHARS_UPDOWN or i == "":
                continue
            else:
                tmpval = "123"
                break
        val = RadioSettingValueString(1, 16, tmpval)
        val.set_charset(DTMF_CHARS_UPDOWN)
        rs = RadioSetting("dtmf_dtmf_up_code",
                          "上线码 (1-16字符 0-9 ABCD*#)", val)
        dtmf.append(rs)

        tmpval = str(_mem.dtmf_settings_numbers.dtmf_down_code).upper().strip(
                "\x00\xff\x20")
        for i in tmpval:
            if i in DTMF_CHARS_UPDOWN:
                continue
            else:
                tmpval = "456"
                break
        val = RadioSettingValueString(1, 16, tmpval)
        val.set_charset(DTMF_CHARS_UPDOWN)
        rs = RadioSetting("dtmf_dtmf_down_code",
                          "下线码 (1-16字符 0-9 ABCD*#)", val)
        dtmf.append(rs)

        tmpval = str(_mem.dtmf_settings_numbers.kill_code).upper().strip(
                "\x00\xff\x20")
        for i in tmpval:
            if i in DTMF_CHARS_KILL:
                continue
            else:
                tmpval = "77777"
                break
        if not len(tmpval) == 5:
            tmpval = "77777"
        val = RadioSettingValueString(5, 5, tmpval)
        val.set_charset(DTMF_CHARS_KILL)
        rs = RadioSetting("dtmf_kill_code",
                          "遥毙码 (5字符 0-9 ABCD)", val)
        dtmf.append(rs)

        tmpval = str(_mem.dtmf_settings_numbers.revive_code).upper().strip(
                "\x00\xff\x20")
        for i in tmpval:
            if i in DTMF_CHARS_KILL:
                continue
            else:
                tmpval = "88888"
                break
        if not len(tmpval) == 5:
            tmpval = "88888"
        val = RadioSettingValueString(5, 5, tmpval)
        val.set_charset(DTMF_CHARS_KILL)
        rs = RadioSetting("dtmf_revive_code",
                          "唤醒码 (5字符 0-9 ABCD)", val)
        dtmf.append(rs)

        val = RadioSettingValueString(0, 80,
                                      "DTMF 联系人为3个字符"
                                      "(有效值: 0-9 * # ABCD), "
                                      "或者是空字符串", charset=VALID_CHARACTERS)
        val.set_mutable(False)
        rs = RadioSetting("dtmf_descr1", "DTMF 联系人", val)
        dtmfc.append(rs)

        for i in range(1, 17):
            varname = "DTMF_" + str(i)
            varnumname = "DTMFNUM_" + str(i)
            vardescr = "联系人" + str(i) + " | 名称"
            varinumdescr = "联系人" + str(i) + " | 号码"

            cntn = str(_mem.dtmfcontact[i-1].name).strip("\x20\x00\xff")
            cntnum = str(_mem.dtmfcontact[i-1].number).strip("\x20\x00\xff")

            val = RadioSettingValueString(0, 8, cntn)
            rs = RadioSetting(varname, vardescr, val)
            dtmfc.append(rs)

            val = RadioSettingValueString(0, 3, cntnum)
            val.set_charset(DTMF_CHARS)
            rs = RadioSetting(varnumname, varinumdescr, val)
            dtmfc.append(rs)

        # MDC 联系人
        val = RadioSettingValueString(0, 80,
                                      "MDC ID 应为 4位16进制数字 例如12AB, 联系人名称不能用中文, 请按顺序添加", charset=VALID_CHARACTERS)
        val.set_mutable(False)
        rs = RadioSetting("mdc_descr1", "MDC 联系人", val)
        mdcc.append(rs)

        for i in range(1, 23):
            mdc_id = "MDC_ID_" + str(i)
            mdc_name = "MDC_NAME_" + str(i)
            mdc_id_descr = "联系人" + str(i) + " | MDC ID"
            mdc_name_descr = "联系人" + str(i) + " | 名称"
            if i <= int(_mem.mdc_num):
                mdc_obj = get_mdc_contact_object(_mem, i)
                c_id = ''.join(['{:02X}'.format(int(byte)) for byte in mdc_obj.id])
                c_name = str(mdc_obj.name)

                val = RadioSettingValueString(0, 4, c_id, charset=' 0123456789ABCDEF')
                rs = RadioSetting(mdc_id, mdc_id_descr, val)
                mdcc.append(rs)

                try:
                    val = RadioSettingValueString(0, 14, c_name)
                except Exception:
                    val = RadioSettingValueString(0, 14, '')
                rs = RadioSetting(mdc_name, mdc_name_descr, val)
                mdcc.append(rs)
            else:
                val = RadioSettingValueString(0, 4, '', charset=' 0123456789ABCDEF')
                rs = RadioSetting(mdc_id, mdc_id_descr, val)
                mdcc.append(rs)

                val = RadioSettingValueString(0, 14, '')
                rs = RadioSetting(mdc_name, mdc_name_descr, val)
                mdcc.append(rs)

        # scanlists
        if _mem.scanlist_default == 1:
            tmpsc = 2
        else:
            tmpsc = 1
        rs = RadioSetting("scanlist_default",
                          "默认扫描列表",
                          RadioSettingValueInteger(1, 2, tmpsc))
        scanl.append(rs)

        tmppr = bool((_mem.scanlist1_priority_scan & 1) > 0)
        rs = RadioSetting(
                "scanlist1_priority_scan",
                "扫描列表1 优先信道扫描",
                RadioSettingValueBoolean(tmppr))
        scanl.append(rs)

        tmpch = _mem.scanlist1_priority_ch1 + 1
        if tmpch > 200:
            tmpch = 0
        rs = RadioSetting("scanlist1_priority_ch1",
                          "扫描列表1 优先信道1 (0 - 关闭)",
                          RadioSettingValueInteger(0, 200, tmpch))
        scanl.append(rs)

        tmpch = _mem.scanlist1_priority_ch2 + 1
        if tmpch > 200:
            tmpch = 0
        rs = RadioSetting("scanlist1_priority_ch2",
                          "扫描列表1 优先信道2 (0 - 关闭)",
                          RadioSettingValueInteger(0, 200, tmpch))
        scanl.append(rs)

        tmppr = bool((_mem.scanlist2_priority_scan & 1) > 0)
        rs = RadioSetting(
                "scanlist2_priority_scan",
                "扫描列表2 优先信道扫描",
                RadioSettingValueBoolean(tmppr))
        scanl.append(rs)

        tmpch = _mem.scanlist2_priority_ch1 + 1
        if tmpch > 200:
            tmpch = 0
        rs = RadioSetting("scanlist2_priority_ch1",
                          "扫描列表2 优先信道1 (0 - 关闭)",
                          RadioSettingValueInteger(0, 200, tmpch))
        scanl.append(rs)

        tmpch = _mem.scanlist2_priority_ch2 + 1
        if tmpch > 200:
            tmpch = 0
        rs = RadioSetting("scanlist2_priority_ch2",
                          "扫描列表2 优先信道2 (0 - 关闭)",
                          RadioSettingValueInteger(0, 200, tmpch))
        scanl.append(rs)

        # basic settings

        # call channel
        tmpc = _mem.call_channel+1
        if tmpc > 200:
            tmpc = 1
        rs = RadioSetting("call_channel", "一键即呼信道",
                          RadioSettingValueInteger(1, 200, tmpc))
        basic.append(rs)

        # squelch
        tmpsq = _mem.squelch
        if tmpsq > 9:
            tmpsq = 1
        rs = RadioSetting("squelch", "静噪等级",
                          RadioSettingValueInteger(0, 9, tmpsq))
        basic.append(rs)

        # TOT
        tmptot = _mem.max_talk_time
        if tmptot > 10:
            tmptot = 10
        rs = RadioSetting(
                "tot",
                "发送超时 [分钟]",
                RadioSettingValueInteger(0, 10, tmptot))
        basic.append(rs)

        # NOAA autoscan
        rs = RadioSetting(
                "noaa_autoscan",
                "NOAA自动扫描", RadioSettingValueBoolean(
                    bool(_mem.noaa_autoscan > 0)))
        basic.append(rs)

        # VOX switch
        rs = RadioSetting(
                "vox_switch",
                "声控发射", RadioSettingValueBoolean(
                    bool(_mem.vox_switch > 0)))
        basic.append(rs)

        # VOX Level
        tmpvox = _mem.vox_level+1
        if tmpvox > 10:
            tmpvox = 10
        rs = RadioSetting("vox_level", "声控发射灵敏度",
                          RadioSettingValueInteger(1, 10, tmpvox))
        basic.append(rs)

        # Mic gain
        tmpmicgain = _mem.mic_gain
        if tmpmicgain > 4:
            tmpmicgain = 2
        rs = RadioSetting("mic_gain", "麦克风增益",
                          RadioSettingValueList(MIC_GAIN_LIST, None, tmpmicgain))
        basic.append(rs)

        # Channel display mode
        tmpchdispmode = _mem.channel_display_mode
        if tmpchdispmode >= len(CHANNELDISP_LIST):
            tmpchdispmode = 0
        rs = RadioSetting(
                "channel_display_mode",
                "信道显示模式",
                RadioSettingValueList(
                    CHANNELDISP_LIST,
                    CHANNELDISP_LIST[tmpchdispmode]))
        basic.append(rs)

        # Crossband receiving/transmitting
        tmpcross = _mem.crossband
        if tmpcross >= len(CROSSBAND_LIST):
            tmpcross = 0
        rs = RadioSetting(
                "crossband",
                "跨段收发",
                RadioSettingValueList(
                    CROSSBAND_LIST,
                    CROSSBAND_LIST[tmpcross]))
        basic.append(rs)

        # Battery save
        tmpbatsave = _mem.battery_save
        if tmpbatsave >= len(BATSAVE_LIST):
            tmpbatsave = BATSAVE_LIST.index("1:4")
        rs = RadioSetting(
                "battery_save",
                "省电模式",
                RadioSettingValueList(
                    BATSAVE_LIST,
                    BATSAVE_LIST[tmpbatsave]))
        basic.append(rs)

        # Dual watch
        tmpdual = _mem.dual_watch
        if tmpdual >= len(DUALWATCH_LIST):
            tmpdual = 0
        rs = RadioSetting("dualwatch", "双频守候", RadioSettingValueList(
            DUALWATCH_LIST, DUALWATCH_LIST[tmpdual]))
        basic.append(rs)

        # Backlight auto mode
        tmpback = _mem.backlight_auto_mode
        if tmpback >= len(BACKLIGHT_LIST):
            tmpback = 0
        rs = RadioSetting("backlight_auto_mode",
                          "自动背光",
                          RadioSettingValueList(
                              BACKLIGHT_LIST,
                              BACKLIGHT_LIST[tmpback]))
        basic.append(rs)

        # Tail tone elimination
        rs = RadioSetting(
                "tail_note_elimination",
                "尾音消除",
                RadioSettingValueBoolean(
                    bool(_mem.tail_note_elimination > 0)))
        basic.append(rs)

        # VFO open
        rs = RadioSetting("vfo_open", "频率模式",
                          RadioSettingValueBoolean(bool(_mem.vfo_open > 0)))
        basic.append(rs)

        # Beep control
        rs = RadioSetting(
                "beep_control",
                "按键音",
                RadioSettingValueBoolean(bool(_mem.beep_control > 0)))
        basic.append(rs)

        # Scan resume mode
        tmpscanres = _mem.scan_resume_mode
        if tmpscanres >= len(SCANRESUME_LIST):
            tmpscanres = 0
        rs = RadioSetting(
                "scan_resume_mode",
                "扫描恢复模式",
                RadioSettingValueList(
                    SCANRESUME_LIST,
                    SCANRESUME_LIST[tmpscanres]))
        basic.append(rs)

        # Keypad locked
        rs = RadioSetting(
                "key_lock",
                "按键锁定",
                RadioSettingValueBoolean(bool(_mem.key_lock > 0)))
        basic.append(rs)

        # Auto keypad lock
        rs = RadioSetting(
                "auto_keypad_lock",
                "按键自动锁定",
                RadioSettingValueBoolean(bool(_mem.auto_keypad_lock > 0)))
        basic.append(rs)

        # Power on display mode
        tmpdispmode = _mem.power_on_dispmode
        if tmpdispmode >= len(WELCOME_LIST):
            tmpdispmode = 0
        rs = RadioSetting(
                "welcome_mode",
                "开机显示",
                RadioSettingValueList(
                    WELCOME_LIST,
                    WELCOME_LIST[tmpdispmode]))
        basic.append(rs)

        # Keypad Tone
        tmpkeypadtone = _mem.keypad_tone
        if tmpkeypadtone >= len(KEYPADTONE_LIST):
            tmpkeypadtone = 0
        rs = RadioSetting("keypad_tone", "按键语音", RadioSettingValueList(
            KEYPADTONE_LIST, KEYPADTONE_LIST[tmpkeypadtone]))
        basic.append(rs)

        # Language
        tmplanguage = _mem.language
        if tmplanguage >= len(LANGUAGE_LIST):
            tmplanguage = 0
        rs = RadioSetting("language", "语言", RadioSettingValueList(
            LANGUAGE_LIST, LANGUAGE_LIST[tmplanguage]))
        basic.append(rs)

        # Alarm mode
        tmpalarmmode = _mem.alarm_mode
        if tmpalarmmode >= len(ALARMMODE_LIST):
            tmpalarmmode = 0
        rs = RadioSetting("alarm_mode", "紧急告警模式", RadioSettingValueList(
            ALARMMODE_LIST, ALARMMODE_LIST[tmpalarmmode]))
        basic.append(rs)

        # Reminding of end of talk
        tmpalarmmode = _mem.reminding_of_end_talk
        if tmpalarmmode >= len(REMENDOFTALK_LIST):
            tmpalarmmode = 0
        rs = RadioSetting(
                "reminding_of_end_talk",
                "首尾音",
                RadioSettingValueList(
                    REMENDOFTALK_LIST,
                    REMENDOFTALK_LIST[tmpalarmmode]))
        basic.append(rs)

        # Repeater tail tone elimination
        tmprte = _mem.repeater_tail_elimination
        if tmprte >= len(RTE_LIST):
            tmprte = 0
        rs = RadioSetting(
                "repeater_tail_elimination",
                "过中继尾音消除",
                RadioSettingValueList(RTE_LIST, RTE_LIST[tmprte]))
        basic.append(rs)

        # Logo string 1
        if self.FIRMWARE_VERSION.endswith('K') or self.FIRMWARE_VERSION.endswith('H'):
            logo1 = convert_bytes_to_chinese(self._welcome_logo[0], self.FIRMWARE_VERSION)
            rs = RadioSetting("logo1", "欢迎字符1 (18字符)",
                              RadioSettingChineseValueString(0, 18, logo1, self.FIRMWARE_VERSION,
                                                             False, VALID_CHARACTERS))
        else:
            logo1 = str(_mem.logo_line1).strip("\x20\x00\xff") + "\x00"
            logo1 = _getstring(logo1.encode('ascii', errors='ignore'), 0, 12)
            rs = RadioSetting("logo1", "欢迎字符1 (12字符)",
                              RadioSettingValueString(0, 12, logo1, False))
        basic.append(rs)

        # Logo string 2
        if self.FIRMWARE_VERSION.endswith('K') or self.FIRMWARE_VERSION.endswith('H'):
            logo2 = convert_bytes_to_chinese(self._welcome_logo[1], self.FIRMWARE_VERSION)
            rs = RadioSetting("logo2", "欢迎字符2 (18字符)",
                              RadioSettingChineseValueString(0, 18, logo2, self.FIRMWARE_VERSION,
                                                             False, VALID_CHARACTERS))
        else:
            logo2 = str(_mem.logo_line2).strip("\x20\x00\xff") + "\x00"
            logo2 = _getstring(logo2.encode('ascii', errors='ignore'), 0, 12)
            rs = RadioSetting("logo2", "欢迎字符2 (12字符)",
                              RadioSettingValueString(0, 12, logo2, False))
        basic.append(rs)

        # FM radio
        for i in range(1, 21):
            freqname = "FM_"+str(i)
            fmfreq = _mem.fmfreq[i-1]/10.0
            if fmfreq < FMMIN or fmfreq > FMMAX:
                rs = RadioSetting(freqname, freqname,
                                  RadioSettingValueString(0, 5, ""))
            else:
                rs = RadioSetting(freqname, freqname,
                                  RadioSettingValueString(0, 5, str(fmfreq)))

            fmradio.append(rs)

        # unlock settings

        # F-LOCK
        tmpflock = _mem.lock_flock
        if tmpflock >= len(FLOCK_LIST):
            tmpflock = 0
        rs = RadioSetting(
            "flock", "频段解锁",
            RadioSettingValueList(FLOCK_LIST, FLOCK_LIST[tmpflock]))
        unlock.append(rs)

        # # 350TX
        # rs = RadioSetting("tx350", "350TX - unlock 350-400 MHz TX",
        #                   RadioSettingValueBoolean(
        #                       bool(_mem.lock.tx350 > 0)))
        # unlock.append(rs)

        # Killed
        rs = RadioSetting("Killed", "遥毙禁用",
                          RadioSettingValueBoolean(
                              bool(_mem.lock_killed > 0)))
        unlock.append(rs)

        # # 200TX
        # rs = RadioSetting("tx200", "200TX - unlock 174-350 MHz TX",
        #                   RadioSettingValueBoolean(
        #                       bool(_mem.lock.tx200 > 0)))
        # unlock.append(rs)
        #
        # # 500TX
        # rs = RadioSetting("tx500", "500TX - unlock 500-600 MHz TX",
        #                   RadioSettingValueBoolean(
        #                       bool(_mem.lock.tx500 > 0)))
        # unlock.append(rs)
        #
        # # 350EN
        # rs = RadioSetting("en350", "350EN - unlock 350-400 MHz RX",
        #                   RadioSettingValueBoolean(
        #                       bool(_mem.lock.en350 > 0)))
        # unlock.append(rs)

        # SCREEN
        rs = RadioSetting("scrambler", "扰频",
                          RadioSettingValueBoolean(
                              bool(_mem.lock_enscramble > 0)))
        unlock.append(rs)

        # readonly info
        # Firmware
        if self.FIRMWARE_VERSION == "":
            firmware = "获取固件版本需要先从电台下载数据"
        else:
            firmware = self.FIRMWARE_VERSION

        val = RadioSettingValueString(0, 128, firmware, charset=VALID_CHARACTERS)
        val.set_mutable(False)
        rs = RadioSetting("fw_ver", "固件版本", val)
        roinfo.append(rs)

        # No limits version for hacked firmware
        val = RadioSettingValueBoolean(self._expanded_limits)
        rs = RadioSetting("nolimits", "禁用限制(适用于第三方固件)",
                          val)
        rs.set_warning(
            '只有在使用宽频的第三方固件时，才应启用此功能。启用此选项将 CHIRP 无视 OEM 限制，可能导致未定义或未规范的行为。风险自负！',
            safe_value=False
        )
        roinfo.append(rs)

        return top

    # Store details about a high-level memory to the memory map
    # This is called when a user edits a memory in the UI
    def set_memory(self, mem):
        number = mem.number-1

        # Get a low-level memory object mapped to the image
        _mem = self._memobj.channel[number]
        _mem4 = self._memobj
        # empty memory
        if mem.empty:
            _mem.set_raw("\xFF" * 16)
            if number < 200:
                _mem2 = self._memobj.channelname[number]
                _mem2.set_raw("\xFF" * 16)
                _mem4.channel_attributes[number].is_scanlist1 = 0
                _mem4.channel_attributes[number].is_scanlist2 = 0
                _mem4.channel_attributes[number].unknown1 = 0
                _mem4.channel_attributes[number].unknown2 = 0
                _mem4.channel_attributes[number].is_free = 1
                _mem4.channel_attributes[number].band = 0x7
            return mem

        # clean the channel memory, restore some bits if it was used before
        if _mem.get_raw(asbytes=False)[0] == "\xff":
            # this was an empty memory
            _mem.set_raw("\x00" * 16)
        else:
            # this memory wasn't empty, save some bits that we don't know the
            # meaning of, or that we don't support yet
            prev_0a = _mem.get_raw()[0x0a] & SAVE_MASK_0A
            prev_0b = _mem.get_raw()[0x0b] & SAVE_MASK_0B
            prev_0c = _mem.get_raw()[0x0c] & SAVE_MASK_0C
            prev_0d = _mem.get_raw()[0x0d] & SAVE_MASK_0D
            prev_0e = _mem.get_raw()[0x0e] & SAVE_MASK_0E
            prev_0f = _mem.get_raw()[0x0f] & SAVE_MASK_0F
            _mem.set_raw("\x00" * 10 +
                         chr(prev_0a) + chr(prev_0b) + chr(prev_0c) +
                         chr(prev_0d) + chr(prev_0e) + chr(prev_0f))

        if number < 200:
            _mem4.channel_attributes[number].is_scanlist1 = 0
            _mem4.channel_attributes[number].is_scanlist2 = 0
            _mem4.channel_attributes[number].unknown1 = 0
            _mem4.channel_attributes[number].unknown2 = 0
            _mem4.channel_attributes[number].is_free = 1
            _mem4.channel_attributes[number].band = 0x7

        # find band
        band = _find_band(self, mem.freq)

        # mode
        if mem.mode == "NFM":
            _mem.bandwidth = 1
            _mem.enable_am = 0
        elif mem.mode == "FM":
            _mem.bandwidth = 0
            _mem.enable_am = 0
        elif mem.mode == "NAM":
            _mem.bandwidth = 1
            _mem.enable_am = 1
        elif mem.mode == "AM":
            _mem.bandwidth = 0
            _mem.enable_am = 1

        # frequency/offset
        _mem.freq = mem.freq/10
        _mem.offset = mem.offset/10

        if mem.duplex == "":
            _mem.offset = 0
            _mem.shift = 0
        elif mem.duplex == '-':
            _mem.shift = FLAGS1_OFFSET_MINUS
        elif mem.duplex == '+':
            _mem.shift = FLAGS1_OFFSET_PLUS
        elif mem.duplex == 'off':
            # we fake tx disable by setting the tx freq to 0 MHz
            _mem.shift = FLAGS1_OFFSET_MINUS
            _mem.offset = _mem.freq

        # set band
        if number < 200:
            _mem4.channel_attributes[number].is_free = 0
            _mem4.channel_attributes[number].band = band

        # channels >200 are the 14 VFO chanells and don't have names
        if number < 200:
            _mem2 = self._memobj.channelname[number]
            text = convert_chinese_to_bytes(mem.name, self.FIRMWARE_VERSION)
            if len(text) < 16:
                text += '\x00' * (16-len(text))
            elif len(text) >= 16:
                text = text[:16]
            _mem2.name = text  # Store the alpha tag

        # tone data
        self._set_tone(mem, _mem)

        # step
        _mem.step = STEPS.index(mem.tuning_step)

        # tx power
        if str(mem.power) == str(UVK5_POWER_LEVELS[2]):
            _mem.txpower = POWER_HIGH
        elif str(mem.power) == str(UVK5_POWER_LEVELS[1]):
            _mem.txpower = POWER_MEDIUM
        else:
            _mem.txpower = POWER_LOW

        for setting in mem.extra:
            sname = setting.get_name()
            svalue = setting.value.get_value()

            if sname == "bclo":
                _mem.bclo = svalue and 1 or 0

            if sname == "pttid":
                _mem.dtmf_pttid = PTTID_LIST.index(svalue)

            if sname == "frev":
                _mem.freq_reverse = svalue and 1 or 0

            if sname == "dtmfdecode":
                _mem.dtmf_decode = svalue and 1 or 0

            if sname == "scrambler":
                _mem.scrambler = (
                    _mem.scrambler & 0xf0) | SCRAMBLER_LIST.index(svalue)

            if number < 200 and sname == "scanlists":
                if svalue == "1":
                    _mem4.channel_attributes[number].is_scanlist1 = 1
                    _mem4.channel_attributes[number].is_scanlist2 = 0
                elif svalue == "2":
                    _mem4.channel_attributes[number].is_scanlist1 = 0
                    _mem4.channel_attributes[number].is_scanlist2 = 1
                elif svalue == "1+2":
                    _mem4.channel_attributes[number].is_scanlist1 = 1
                    _mem4.channel_attributes[number].is_scanlist2 = 1
                else:
                    _mem4.channel_attributes[number].is_scanlist1 = 0
                    _mem4.channel_attributes[number].is_scanlist2 = 0

        return mem
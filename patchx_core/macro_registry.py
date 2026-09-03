# -*- coding: utf-8 -*-
"""Kho macro Smali kế thừa và tối ưu từ Modder Hub, có kiểm tra register trước khi dùng."""

import re

MACROS = {
    "toast_status": (
        "const/4 v1, 0x1\n"
        "invoke-static {p0, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;\n"
        "move-result-object v0\n"
        "invoke-virtual {v0}, Landroid/widget/Toast;->show()V"
    ),
    "logcat_interceptor": (
        'const-string v0, "PatchX"\n'
        "invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    ),
    "return_true": (
        "const/4 v0, 0x1\n"
        "return v0"
    ),
    "return_false": (
        "const/4 v0, 0x0\n"
        "return v0"
    ),
    "return_null": (
        "const/4 v0, 0x0\n"
        "return-object v0"
    ),
    "return_void": (
        "return-void"
    ),
    "kill_process": (
        "invoke-static {}, Landroid/os/Process;->myPid()I\n"
        "move-result v0\n"
        "invoke-static {v0}, Landroid/os/Process;->killProcess(I)V"
    ),
    "trust_manager_template": (
        ".method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V\n"
        "    .locals 0\n"
        "    return-void\n"
        ".end method\n\n"
        ".method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V\n"
        "    .locals 0\n"
        "    return-void\n"
        ".end method\n\n"
        ".method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;\n"
        "    .locals 1\n"
        "    const/4 v0, 0x0\n"
        "    new-array v0, v0, [Ljava/security/cert/X509Certificate;\n"
        "    return-object v0\n"
        ".end method"
    ),
    "revenuecat_is_active": (
        "const/4 v0, 0x1\n"
        "return v0"
    ),
    "admob_reward_instant_callback": (
        "if-eqz p1, :cond_reward_end\n"
        "const/4 v0, 0x0\n"
        "invoke-interface {p1, v0}, Lcom/google/android/gms/ads/OnUserEarnedRewardListener;->onUserEarnedReward(Lcom/google/android/gms/ads/rewarded/RewardItem;)V\n"
        ":cond_reward_end\n"
        "return-void"
    ),
    "device_id_randomizer": (
        "invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;\n"
        "move-result-object v0\n"
        "invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;\n"
        "move-result-object v0\n"
        "return-object v0"
    ),
    "remote_config_force_true": (
        "const/4 v0, 0x1\n"
        "return v0"
    ),
}


def list_macros():
    """Liệt kê danh sách tên các macro đã đăng ký."""
    return sorted(MACROS.keys())


def get_macro(name):
    """Lấy nội dung macro theo tên."""
    if name not in MACROS:
        raise KeyError("Không tìm thấy macro: %s" % name)
    return MACROS[name]


def required_registers(snippet):
    """Tính số register local v cần thiết tối thiểu cho macro snippet."""
    v_regs = set(re.findall(r"\bv(\d+)\b", snippet))
    if not v_regs:
        return 0
    return max(int(x) for x in v_regs) + 1


def validate_macro(name, registers):
    """Kiểm tra xem số registers cấp phát có an toàn cho macro không."""
    if registers < 0:
        raise ValueError("registers phải >= 0")
    need = required_registers(get_macro(name))
    return {
        "name": name,
        "registers": registers,
        "required_registers": need,
        "safe": registers >= need,
    }

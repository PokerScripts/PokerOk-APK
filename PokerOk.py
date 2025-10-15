#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Автор: PokerScripts
"""

import os
import sys
import argparse
import hashlib
import zipfile
from datetime import datetime
from pathlib import Path

# Импортируем androguard для анализа структуры APK
try:
    from androguard.core.bytecodes.apk import APK
except ImportError:
    print("Ошибка: не установлен пакет androguard.\nУстановите его командой:")
    print("    pip install androguard")
    sys.exit(1)


# -------------------------------------------------------
# Функция вычисления хэшей MD5 и SHA256
# -------------------------------------------------------
def compute_hashes(file_path, chunk_size=4 * 1024 * 1024):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            md5.update(data)
            sha256.update(data)
    return md5.hexdigest(), sha256.hexdigest()


# -------------------------------------------------------
# Чтение общей информации о файле (размер, дата и т.д.)
# -------------------------------------------------------
def read_file_stats(file_path):
    size_bytes = os.path.getsize(file_path)
    size_mb = size_bytes / (1024 * 1024)
    mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
    abs_path = os.path.abspath(file_path)
    return {
        "file_name": os.path.basename(file_path),
        "abs_path": abs_path,
        "size_bytes": size_bytes,
        "size_mb": size_mb,
        "modified": mtime.strftime("%Y-%m-%d %H:%M:%S"),
    }


# -------------------------------------------------------
# Анализ APK-файла с помощью androguard
# -------------------------------------------------------
def analyze_apk(apk_path):
    apk = APK(apk_path)
    data = {}
    data["package"] = apk.get_package() or "нет данных"
    data["version_name"] = apk.get_androidversion_name() or "нет данных"
    data["version_code"] = apk.get_androidversion_code() or "нет данных"
    data["min_sdk"] = apk.get_min_sdk_version() or "нет данных"
    data["target_sdk"] = apk.get_target_sdk_version() or "нет данных"
    data["permissions"] = apk.get_permissions() or []
    data["main_activity"] = apk.get_main_activity() or "нет данных"
    data["app_name"] = apk.get_app_name() or "нет данных"

    # Проверяем некоторые атрибуты из AndroidManifest.xml
    manifest = apk.get_android_manifest_axml()
    app_tag = manifest.find("application")
    if app_tag is not None:
        data["debuggable"] = app_tag.get("android:debuggable", "нет данных")
        data["allow_backup"] = app_tag.get("android:allowBackup", "нет данных")
    else:
        data["debuggable"] = "нет данных"
        data["allow_backup"] = "нет данных"

    return data


# -------------------------------------------------------
# Извлекаем архитектуры (ABI) и языковые ресурсы
# -------------------------------------------------------
def inspect_zip_for_abis_and_locales(apk_path):
    abis = set()
    locales = set()
    with zipfile.ZipFile(apk_path, "r") as zip_ref:
        for name in zip_ref.namelist():
            # Проверяем архитектуры
            if name.startswith("lib/") and name.count("/") >= 2:
                abi = name.split("/")[1]
                abis.add(abi)
            # Проверяем языковые квалификаторы
            if name.startswith("res/values-") and name.endswith("/strings.xml"):
                locale = name.split("/")[1].replace("values-", "")
                locales.add(locale)
            elif name.startswith("res/values/strings.xml"):
                locales.add("default")
    return sorted(abis), sorted(locales)


# -------------------------------------------------------
# Извлечение информации о подписи (сертификате)
# -------------------------------------------------------
def extract_signing_info(apk_obj):
    try:
        certs = apk_obj.get_certificates_der_v2()
        if not certs:
            certs = apk_obj.get_certificates_der_v3()
        if not certs:
            certs = apk_obj.get_certificates_der_v1()
        if not certs:
            return {"signed": "нет", "cert_sha1": "нет данных"}

        # Берём первый сертификат и считаем SHA1
        cert_data = certs[0]
        sha1 = hashlib.sha1(cert_data).hexdigest().upper()
        sha1_fmt = ":".join(sha1[i:i + 2] for i in range(0, len(sha1), 2))
        return {"signed": "да", "cert_sha1": sha1_fmt}
    except Exception:
        return {"signed": "нет данных", "cert_sha1": "нет данных"}


# -------------------------------------------------------
# Формирование текстового отчёта
# -------------------------------------------------------
def render_report(file_stats, md5, sha256, meta, abis, locales, signing):
    lines = []
    lines.append("=== PokerOk APK Report ===")
    lines.append(f"Дата и время генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("[Файл]")
    lines.append(f"Имя файла: {file_stats['file_name']}")
    lines.append(f"Абсолютный путь: {file_stats['abs_path']}")
    lines.append(f"Размер: {file_stats['size_bytes']} байт ({file_stats['size_mb']:.2f} MB)")
    lines.append(f"SHA256: {sha256}")
    lines.append(f"MD5: {md5}")
    lines.append(f"Последнее изменение: {file_stats['modified']}")
    lines.append("")
    lines.append("[Приложение]")
    lines.append(f"Package name: {meta['package']}")
    lines.append(f"VersionName: {meta['version_name']}")
    lines.append(f"VersionCode: {meta['version_code']}")
    lines.append(f"minSdkVersion: {meta['min_sdk']}")
    lines.append(f"targetSdkVersion: {meta['target_sdk']}")
    lines.append(f"App label: {meta['app_name']}")
    lines.append(f"Main activity: {meta['main_activity']}")
    lines.append(f"Debuggable: {meta['debuggable']}")
    lines.append(f"AllowBackup: {meta['allow_backup']}")
    lines.append("")
    lines.append("[Разрешения]")
    if meta["permissions"]:
        for p in meta["permissions"]:
            lines.append(f"- {p}")
    else:
        lines.append("нет данных")
    lines.append("")
    lines.append("[Архитектуры (lib/*)]")
    if abis:
        for abi in abis:
            lines.append(f"- {abi}")
    else:
        lines.append("нет данных")
    lines.append("")
    lines.append("[Языковые ресурсы]")
    if locales:
        for loc in locales:
            lines.append(f"- {loc}")
    else:
        lines.append("нет данных")
    lines.append("")
    lines.append("[Информация о подписи]")
    lines.append(f"Подписан: {signing['signed']}")
    lines.append(f"Сертификат (SHA1): {signing['cert_sha1']}")
    lines.append("")
    lines.append("[Сводка]")
    lines.append(f"Permissions: {len(meta['permissions'])}")
    lines.append(f"ABIs: {len(abis)}")
    lines.append(f"Locales: {len(locales)}")

    return "\n".join(lines)


# -------------------------------------------------------
# Основная функция
# -------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Анализатор файла PokerOk.apk")
    parser.add_argument("--apk", "-a", default="PokerOk.apk", help="путь к APK файлу (по умолчанию PokerOk.apk)")
    parser.add_argument("--out", "-o", default="PokerOk_report.txt", help="путь к выходному отчёту (по умолчанию PokerOk_report.txt)")
    args = parser.parse_args()

    apk_path = Path(args.apk)
    out_path = Path(args.out)

    # Проверяем существование файла
    if not apk_path.exists():
        print(f"Ошибка: файл не найден: {apk_path}")
        sys.exit(1)

    try:
        # Получаем информацию о файле
        file_stats = read_file_stats(apk_path)
        md5, sha256 = compute_hashes(apk_path)

        # Анализ APK
        apk_obj = APK(apk_path)
        meta = analyze_apk(apk_path)
        abis, locales = inspect_zip_for_abis_and_locales(apk_path)
        signing = extract_signing_info(apk_obj)

        # Формируем отчёт
        report = render_report(file_stats, md5, sha256, meta, abis, locales, signing)

        # Сохраняем результат
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"Отчёт успешно создан: {out_path}")
        sys.exit(0)

    except Exception as e:
        print(f"Ошибка при анализе APK: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
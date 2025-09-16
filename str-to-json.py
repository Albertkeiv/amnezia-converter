#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Декодирование строки vpn://<base64_url_no_padding> обратно в текст конфига.
Без парсинга — просто вернуть исходный текст.
"""

import argparse
import base64
import logging
import struct
import sys
import zlib
from pathlib import Path

VPN_PREFIX = "vpn://"


def quncompress(blob: bytes) -> bytes:
    """Обратное к qCompress: 4 байта длины (big-endian) + zlib-поток."""
    if len(blob) < 5:
        raise ValueError("Недостаточная длина для qUncompress")
    orig_len = struct.unpack(">I", blob[:4])[0]
    raw = zlib.decompress(blob[4:])
    if orig_len != len(raw):
        logging.warning("Ожидалась длина %d, фактическая %d", orig_len, len(raw))
    return raw


def decode_vpn_string(s: str) -> str:
    """Принять строку с/без префикса vpn:// и вернуть исходный текст."""
    s = s.strip()
    if s.startswith(VPN_PREFIX):
        s = s[len(VPN_PREFIX):]

    # Восстановить padding для Base64 URL-safe
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad

    try:
        compressed = base64.urlsafe_b64decode(s.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Ошибка Base64: {e}") from e

    try:
        data = quncompress(compressed)
    except Exception as e:
        raise ValueError(f"Ошибка распаковки: {e}") from e

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"Ошибка UTF-8: {e}") from e


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Декодировать vpn://<base64> в исходный текст конфига"
    )
    parser.add_argument(
        "input",
        help="Строка vpn://<...> или путь к файлу с этой строкой",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Тише (WARNING)"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    source = args.input
    p = Path(source)
    if p.exists() and p.is_file():
        try:
            source = p.read_text(encoding="utf-8").strip()
        except Exception as e:
            logging.error("Не удалось прочитать файл: %s", e)
            sys.exit(1)

    try:
        text = decode_vpn_string(source)
    except Exception as e:
        logging.error("%s", e)
        sys.exit(2)

    # Печатаем исходную конфигурацию
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()

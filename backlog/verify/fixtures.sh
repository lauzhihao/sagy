#!/usr/bin/env bash
# 固定测试数据。全部为离线可判定的构造值, 不含任何真实凭据。
# EXPIRED_JWT 的 exp = 1000000000 (2001-09-09), 必定过期
# FRESH_JWT   的 exp = 4102444800 (2100-01-01), 必定未过期
EXPIRED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMDAwMDAsImVtYWlsIjoiZXhwaXJlZEBleGFtcGxlLmNvbSJ9.sig"
FRESH_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDAsImVtYWlsIjoiZnJlc2hAZXhhbXBsZS5jb20ifQ.sig"

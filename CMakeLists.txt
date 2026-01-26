# Copyright (c) 2026 PICMG

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(iot_foundry_zephyr_endpoint)

zephyr_syscall_include_directories(include)
zephyr_include_directories(include)

target_sources(app PRIVATE src/main.c src/mctp_control.c)

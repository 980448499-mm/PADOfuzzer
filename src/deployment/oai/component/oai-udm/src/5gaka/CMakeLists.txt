# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(5GAKA_DIR "${SRC_TOP_DIR}/5gaka")

include_directories(${SRC_TOP_DIR}/udm_app)
include_directories(${SRC_TOP_DIR}/udm_app/event_handling)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/5gaka)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/ngap/libngap)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

# Cryptopp: prefer project-local cryptopp 8.x if system cryptopp lacks xed25519.h (< 8.0)
if(NOT EXISTS "/usr/include/cryptopp/xed25519.h")
    if(EXISTS "${BUILD_TOP_DIR}/ext/cryptopp/include/cryptopp/xed25519.h")
        include_directories(${BUILD_TOP_DIR}/ext/cryptopp/include)
    elseif(EXISTS "$ENV{OPENAIRCN_DIR}/build/ext/cryptopp/include/cryptopp/xed25519.h")
        include_directories($ENV{OPENAIRCN_DIR}/build/ext/cryptopp/include)
    else()
        message(WARNING "5GAKA: cryptopp >= 8.0 not found, suci.cpp compilation will fail")
    endif()
endif()

file(GLOB 5GAKA_src_files
    ${SRC_TOP_DIR}/${MOUNTED_COMMON}/ngap/libngap/*.c
    ${5GAKA_DIR}/*.cpp
)
 
add_library(5GAKA STATIC
           ${5GAKA_src_files})        

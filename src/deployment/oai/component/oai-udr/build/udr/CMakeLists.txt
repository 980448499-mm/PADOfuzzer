# SPDX-License-Identifier: LicenseRef-CSSL-1.0

cmake_minimum_required (VERSION 3.0.2)
project(oai-cn)

enable_testing()

# Override options for UDR
set (  PACKAGE_NAME                    "UDR" )
set (  STATIC_LINKING                  False )
#############################################
# Base directories, compatible with legacy OAI building
################################################
set (OPENAIRCN_DIR   $ENV{OPENAIRCN_DIR})
set (BUILD_TOP_DIR   ${OPENAIRCN_DIR}/build)
set (SRC_TOP_DIR     $ENV{OPENAIRCN_DIR}/src)

################################################
# For common-src usage
################################################
set (  NF_TARGET                        udr )
set (  MOUNTED_COMMON                   common-src)


include(${CMAKE_CURRENT_SOURCE_DIR}/../../src/oai_udr/CMakeLists.txt)

ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/udr_app ${CMAKE_CURRENT_BINARY_DIR}/udr_app)
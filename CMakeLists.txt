##
# pam_flag - PAM module to flag users recently authenticated
# Copyright (C) 2025 Anna-Sophie Kasierocka
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
##

cmake_minimum_required(VERSION 3.10)

project(pam_flag C)

# Build the PAM module from the source file
add_library(pam_flag MODULE src/pam_flag.c)

# Add flags to compiler
target_compile_options(pam_flag PRIVATE
        -fPIC
        -Werror
        -Wall
        -Wextra
        -O2
        -fstack-protector-strong
        -fPIE
        -Wl,-z,relro,-z,now
        -Wformat=2
        -Wconversion
        -Wshadow
        -fno-common
        -D_FORTIFY_SOURCE=3
)

# PAM modules should not have the default "lib" prefix and should be named pam_*
set_target_properties(pam_flag PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pam_flag"
)

# Find and link against libpam
find_library(PAM_LIBRARY pam)
if(NOT PAM_LIBRARY)
    message(FATAL_ERROR "libpam not found. Please install the PAM development package (e.g., libpam0g-dev or pam-devel).")
endif()

target_link_libraries(pam_flag PRIVATE ${PAM_LIBRARY})

# Optionally, provide an install rule (OFF by default due to system-specific path)
option(INSTALL_PAM_MODULE "Install the PAM module to a system directory" OFF)
if(INSTALL_PAM_MODULE)
    # Common locations: /lib/security or /usr/lib/security (varies by distro and arch)
    set(PAM_MODULE_INSTALL_DIR "/usr/lib/security" CACHE PATH "Destination for PAM modules")
    install(TARGETS pam_flag LIBRARY DESTINATION ${PAM_MODULE_INSTALL_DIR})
endif()

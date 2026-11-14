cmake_minimum_required(VERSION 3.15)
project(ProcessDumper CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DUNICODE -D_UNICODE -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00)

file(GLOB SOURCES 
    "src/*.cpp"
)

add_executable(ProcessDumper WIN32 ${SOURCES})

target_include_directories(ProcessDumper PRIVATE src)

target_link_libraries(ProcessDumper PRIVATE
    comctl32
    psapi
    dwmapi
    uxtheme
    shell32
    gdi32
    user32
    kernel32
    advapi32
)

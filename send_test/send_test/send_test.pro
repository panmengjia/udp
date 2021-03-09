QT -= gui
QT -= core

CONFIG += c++11 console
CONFIG -= app_bundle

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += main.cpp

#INCLUDEPATH += /usr/include/opencv4 \
#               /usr/include/opencv4/opencv2 \
#                /usr/src/tegra_multimedia_api/argus/include/Argus \


#LIBS += /usr/lib/aarch64-linux-gnu/libopencv_core.so   \
#        /usr/lib/aarch64-linux-gnu/libopencv_highgui.so \
#        /usr/lib/aarch64-linux-gnu/libopencv_imgproc.so\
#        /usr/lib/aarch64-linux-gnu/libopencv_imgcodecs.so\
#        /usr/lib/aarch64-linux-gnu/libopencv_videoio.so




#LIBS += -L//usr/lib/x86_64-linux-gnu -lpcap

#INCLUDEPATH +=/usr/include/python2.7/
#INCLUDEPATH +=/usr/include/
#INCLUDEPATH +=/usr/local/include/
## LIBS += -lboost_python -lpython2.7 -lboost_system


#LIBS += -pthread
#QMAKE_CXXFLAGS += -std=c++11 -g
#QMAKE_CFLAGS_ISYSTEM = -I


#-----------------------start----------himix200 3516------------------------------
TARGET = himix200_send_test0309
DESTDIR =/home/hisilicon/Desktop/nfs_3516dv300/udpcommunication/send_test

INCLUDEPATH +=/home/hisilicon/Desktop/hisilicon3516/udp/lib_build/libpcapinstall/include/
LIBS += \
        /home/hisilicon/Downloads/libpcap-libpcap-1.7.4/libpcap.a

#LIBS += \
#    ../../../../../../../opt/hisi-linux/x86-arm/arm-himix200-linux/target/lib/*.so*
#LIBS +=/opt/hisi-linux/x86-arm/arm-himix200-linux/target/lib/ -lpthread -lrt
#------------------------end-----------himix200 3516------------------------------



#-----------------------start----------himix100 3559------------------------------

#TARGET = himix100_send_test_3559
#DESTDIR =/home/hisilicon/Desktop/nfs_v300/udpcommunication/send_test

#INCLUDEPATH +=/home/hisilicon/Desktop/hisilicon3516/udp/lib_build/libpcap-libpcap-1.7.4-3559-himix100-Install/include/

#LIBS+=/home/hisilicon/Desktop/hisilicon3516/udp/lib_build/libpcap-libpcap-1.7.4-3559-himix100-Install/lib/libpcap.a

#------------------------end-----------himix100 3559------------------------------

##############################ubuntu x86_64#################################################################
#QMAKE_LIBDIR_FLAGS +=-/home/hisilicon/Downloads/libpcap-libpcap-1.10.0-x86_64/libpcap-libpcap-1.10.0/ -Wl,R

#INCLUDEPATH +=/home/hisilicon/Desktop/hisilicon3516/udp/ubuntu_x86_64/libpcap-master_Install/include

#LIBS += \
#        /home/hisilicon/Desktop/hisilicon3516/udp/ubuntu_x86_64/libpcap-master_Install/lib/libpcap.a \
#        /usr/lib/x86_64-linux-gnu/libdbus-1.a \
#        /lib/x86_64-linux-gnu/libsystemd.so.0

#INCLUDEPATH +=/home/hisilicon/Desktop/hisilicon3516/udp/lib_build/libpcap-libpcap-1.7.4-3559-himix100-Install/include/

#LIBS += /home/hisilicon/Downloads/libpcap-libpcap-1.10.0-x86_64/libpcap-libpcap-1.10.0/libpcap.a \
#/usr/lib/x86_64-linux-gnu/libdbus-1.a \
#/lib/x86_64-linux-gnu/libsystemd.so.0

#/usr/lib/x86_64-linux-gnu/libdbus-1.so

##############################ubuntu x86_64#################################################################


QMAKE_CXXFLAGS += -std=c++11 -g

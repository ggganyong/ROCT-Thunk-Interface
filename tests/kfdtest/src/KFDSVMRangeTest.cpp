/*
 * Copyright (C) 2020 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#include "KFDSVMRangeTest.hpp"
#include <sys/mman.h>
#include <vector>
#include "PM4Queue.hpp"
#include "PM4Packet.hpp"
#include "SDMAPacket.hpp"
#include "SDMAQueue.hpp"
#include "Dispatch.hpp"

void KFDSVMRangeTest::SetUp() {
    ROUTINE_START

    KFDBaseComponentTest::SetUp();

    m_pIsaGen = IsaGenerator::Create(m_FamilyId);

    ROUTINE_END
}

void KFDSVMRangeTest::TearDown() {
    ROUTINE_START

    if (m_pIsaGen)
        delete m_pIsaGen;
    m_pIsaGen = NULL;

    KFDBaseComponentTest::TearDown();

    ROUTINE_END
}

TEST_F(KFDSVMRangeTest, BasicSystemMemTest) {
    TEST_REQUIRE_ENV_CAPABILITIES(ENVCAPS_64BITLINUX);
    TEST_START(TESTPROFILE_RUNALL);

    PM4Queue queue;
    HSAuint64 AlternateVAGPU;
    unsigned int BufferSize = PAGE_SIZE;

    int defaultGPUNode = m_NodeInfo.HsaDefaultGPUNode();
    ASSERT_GE(defaultGPUNode, 0) << "failed to get default GPU Node";

    if (!GetVramSize(defaultGPUNode)) {
        LOG() << "Skipping test: No VRAM found." << std::endl;
        return;
    }

    HsaMemoryBuffer isaBuffer(PAGE_SIZE, defaultGPUNode);
    HsaSVMRange srcSysBuffer(BufferSize, defaultGPUNode);
    HsaSVMRange destSysBuffer(BufferSize, defaultGPUNode);

    srcSysBuffer.Fill(0x01010101);

    m_pIsaGen->GetCopyDwordIsa(isaBuffer);

    ASSERT_SUCCESS(queue.Create(defaultGPUNode));
    queue.SetSkipWaitConsump(0);

    Dispatch dispatch(isaBuffer);

    dispatch.SetArgs(srcSysBuffer.As<void*>(), destSysBuffer.As<void*>());
    dispatch.Submit(queue);
    dispatch.Sync(g_TestTimeOut);

    EXPECT_SUCCESS(queue.Destroy());

    EXPECT_EQ(destSysBuffer.As<unsigned int*>()[0], 0x01010101);

    TEST_END
}

TEST_F(KFDSVMRangeTest, SetGetAttributesTest) {
    TEST_REQUIRE_ENV_CAPABILITIES(ENVCAPS_64BITLINUX);
    TEST_START(TESTPROFILE_RUNALL)

    int defaultGPUNode = m_NodeInfo.HsaDefaultGPUNode();
    ASSERT_GE(defaultGPUNode, 0) << "failed to get default GPU Node";

    if (m_FamilyId < FAMILY_AI) {
        LOG() << std::hex << "Skipping test: No svm range support for family ID 0x" << m_FamilyId << "." << std::endl;
        return;
    }

    int i;
    unsigned int BufSize = PAGE_SIZE;
    HsaSVMRange *sysBuffer;
    HSAuint32 nAttributes = 5;
    HSA_SVM_ATTRIBUTE outputAttributes[nAttributes];
    HSA_SVM_ATTRIBUTE inputAttributes[] = {
                                                {HSA_SVM_ATTR_PREFETCH_LOC, (HSAuint32)defaultGPUNode},
                                                {HSA_SVM_ATTR_PREFERRED_LOC, (HSAuint32)defaultGPUNode},
                                                {HSA_SVM_ATTR_SET_FLAGS,
                                                 HSA_SVM_FLAG_HOST_ACCESS | HSA_SVM_FLAG_GPU_EXEC | HSA_SVM_FLAG_COHERENT},
                                                {HSA_SVM_ATTR_GRANULARITY, 0xFF},
                                                {HSA_SVM_ATTR_ACCESS, (HSAuint32)defaultGPUNode},
                                          };

    HSAuint32 expectedDefaultResults[] = {
                                             0,
                                             0,
                                             HSA_SVM_FLAG_HOST_ACCESS | HSA_SVM_FLAG_COHERENT,
                                             9,
                                             0,
                                         };
    HSAint32 enable = -1;
    EXPECT_SUCCESS(hsaKmtGetXNACKMode(&enable));
    expectedDefaultResults[4] = (enable)?HSA_SVM_ATTR_ACCESS:HSA_SVM_ATTR_NO_ACCESS;
    sysBuffer = new HsaSVMRange(BufSize);
    char *pBuf = sysBuffer->As<char *>();

    LOG() << "Get default atrributes" << std::endl;
    memcpy(outputAttributes, inputAttributes, nAttributes * sizeof(HSA_SVM_ATTRIBUTE));
    EXPECT_SUCCESS(hsaKmtSVMGetAttr(pBuf, BufSize,
                                    nAttributes, outputAttributes));

    for (i = 0; i < nAttributes; i++) {
        if (outputAttributes[i].type == HSA_SVM_ATTR_ACCESS ||
            outputAttributes[i].type == HSA_SVM_ATTR_ACCESS_IN_PLACE ||
            outputAttributes[i].type == HSA_SVM_ATTR_NO_ACCESS)
            EXPECT_EQ(outputAttributes[i].type, expectedDefaultResults[i]);
        else
            EXPECT_EQ(outputAttributes[i].value, expectedDefaultResults[i]);
    }
    LOG() << "Setting/Getting atrributes" << std::endl;
    memcpy(outputAttributes, inputAttributes, nAttributes * sizeof(HSA_SVM_ATTRIBUTE));
    EXPECT_SUCCESS(hsaKmtSVMSetAttr(pBuf, BufSize,
                                    nAttributes, inputAttributes));
    EXPECT_SUCCESS(hsaKmtSVMGetAttr(pBuf, BufSize,
                                    nAttributes, outputAttributes));
   for (i = 0; i < nAttributes; i++) {
        if (outputAttributes[i].type == HSA_SVM_ATTR_ACCESS ||
            outputAttributes[i].type == HSA_SVM_ATTR_ACCESS_IN_PLACE ||
            outputAttributes[i].type == HSA_SVM_ATTR_NO_ACCESS)
            EXPECT_EQ(inputAttributes[i].type, outputAttributes[i].type);
        else
            EXPECT_EQ(inputAttributes[i].value, outputAttributes[i].value);
   }

    TEST_END
}

TEST_F(KFDSVMRangeTest, XNACKModeTest) {
    TEST_REQUIRE_ENV_CAPABILITIES(ENVCAPS_64BITLINUX);
    TEST_START(TESTPROFILE_RUNALL);

    HSAuint32 i, j;
    HSAint32 r;
    PM4Queue queue;
    HSAint32 enable = 0;
    const std::vector<int> gpuNodes = m_NodeInfo.GetNodesWithGPU();

    EXPECT_SUCCESS(hsaKmtGetXNACKMode(&enable));
    for (i = 0; i < 2; i++) {
        enable = !enable;
        r = hsaKmtSetXNACKMode(enable);
        if (r == HSAKMT_STATUS_SUCCESS) {
            LOG() << "XNACK mode: " << std::boolalpha << enable <<
                     " supported" << std::endl;

            for (j = 0; j < gpuNodes.size(); j++) {
                LOG() << "Creating queue and try to set xnack mode on node: "
                      << gpuNodes.at(j) << std::endl;
                ASSERT_SUCCESS(queue.Create(gpuNodes.at(j)));
                EXPECT_EQ(HSAKMT_STATUS_ERROR,
                        hsaKmtSetXNACKMode(enable));
                EXPECT_SUCCESS(queue.Destroy());
            }
        } else if (r == HSAKMT_STATUS_NOT_SUPPORTED) {
            LOG() << "XNACK mode: " << std::boolalpha << enable <<
                     " NOT supported" << std::endl;
        }
    }
    TEST_END
}

TEST_F(KFDSVMRangeTest, InvalidRangeTest) {
    TEST_START(TESTPROFILE_RUNALL)

    HSAuint32 Flags;;
    HSAKMT_STATUS ret;

    int defaultGPUNode = m_NodeInfo.HsaDefaultGPUNode();
    ASSERT_GE(defaultGPUNode, 0) << "failed to get default GPU Node";

    Flags = HSA_SVM_FLAG_HOST_ACCESS | HSA_SVM_FLAG_COHERENT;

    ret = RegisterSVMRange(defaultGPUNode, reinterpret_cast<void *>(0x10000), 0x1000, 0, Flags);
    EXPECT_NE(ret, HSAKMT_STATUS_SUCCESS);

    TEST_END
}

void KFDSVMRangeTest::SplitRangeTest(int defaultGPUNode, int prefetch_location) {
    unsigned int BufSize = 16 * PAGE_SIZE;

    HsaSVMRange *sysBuffer;
    HsaSVMRange *sysBuffer2;
    HsaSVMRange *sysBuffer3;
    HsaSVMRange *sysBuffer4;

    void *pBuf;

    // case 1
    pBuf = mmap(0, BufSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(pBuf, BufSize, defaultGPUNode, prefetch_location);
    sysBuffer2 = new HsaSVMRange(reinterpret_cast<char *>(pBuf) + 8192, PAGE_SIZE, defaultGPUNode, prefetch_location);
    delete sysBuffer2;
    delete sysBuffer;
    munmap(pBuf, BufSize);

    // case 2.1
    pBuf = mmap(0, BufSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(pBuf, BufSize, defaultGPUNode, prefetch_location);
    sysBuffer2 = new HsaSVMRange(reinterpret_cast<char *>(pBuf) + 4096, BufSize - 4096, defaultGPUNode,
                                 prefetch_location);
    delete sysBuffer2;
    delete sysBuffer;
    munmap(pBuf, BufSize);

    // case 2.2
    pBuf = mmap(0, BufSize + 8192, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(pBuf, BufSize, defaultGPUNode, prefetch_location);
    sysBuffer2 = new HsaSVMRange(reinterpret_cast<char *>(pBuf) + 8192, BufSize, defaultGPUNode, prefetch_location);
    delete sysBuffer2;
    delete sysBuffer;
    munmap(pBuf, BufSize + 8192);

    // case 3
    pBuf = mmap(0, BufSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(pBuf, BufSize, defaultGPUNode, prefetch_location);
    sysBuffer2 = new HsaSVMRange(reinterpret_cast<char *>(pBuf), BufSize - 8192, defaultGPUNode, prefetch_location);
    delete sysBuffer2;
    delete sysBuffer;
    munmap(pBuf, BufSize);

    // case 4.1
    pBuf = mmap(0, BufSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(pBuf, BufSize, defaultGPUNode, prefetch_location);
    sysBuffer2 = new HsaSVMRange(pBuf, BufSize, defaultGPUNode, prefetch_location);
    delete sysBuffer2;
    delete sysBuffer;
    munmap(pBuf, BufSize);

    // case 4.2
    pBuf = mmap(0, BufSize + 8192, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(pBuf, BufSize, defaultGPUNode, prefetch_location);
    sysBuffer2 = new HsaSVMRange(pBuf, BufSize + 8192, defaultGPUNode, prefetch_location);
    delete sysBuffer2;
    delete sysBuffer;
    munmap(pBuf, BufSize + 8192);

    // case 5
    pBuf = mmap(0, BufSize + 65536, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(reinterpret_cast<char *>(pBuf) + 8192, 8192, defaultGPUNode, prefetch_location);
    sysBuffer2 = new HsaSVMRange(reinterpret_cast<char *>(pBuf) + 32768, 8192, defaultGPUNode, prefetch_location);
    sysBuffer3 = new HsaSVMRange(pBuf, BufSize + 65536, defaultGPUNode, prefetch_location);
    delete sysBuffer2;
    delete sysBuffer3;
    delete sysBuffer;
    munmap(pBuf, BufSize + 65536);

    // case 6, unregister after free
    pBuf = mmap(0, BufSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sysBuffer = new HsaSVMRange(reinterpret_cast<char *>(pBuf) + 8192, 8192, defaultGPUNode, prefetch_location);
    munmap(pBuf, BufSize);
    delete sysBuffer;
}

TEST_F(KFDSVMRangeTest, SplitSystemRangeTest) {
    const HsaNodeProperties *pNodeProperties = m_NodeInfo.HsaDefaultGPUNodeProperties();
    TEST_START(TESTPROFILE_RUNALL)

    int defaultGPUNode = m_NodeInfo.HsaDefaultGPUNode();
    ASSERT_GE(defaultGPUNode, 0) << "failed to get default GPU Node";

    if (m_FamilyId < FAMILY_AI) {
        LOG() << std::hex << "Skipping test: No svm range support for family ID 0x" << m_FamilyId << "." << std::endl;
        return;
    }

    SplitRangeTest(defaultGPUNode, 0);

    TEST_END
}

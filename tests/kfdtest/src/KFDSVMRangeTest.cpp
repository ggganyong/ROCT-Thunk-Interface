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
    HSAuint32 xnackNumNodes = 1;
    HSAuint32 xnackNode[xnackNumNodes];
    HSAint32 enable = -1;
    EXPECT_SUCCESS(hsaKmtGetXNACKMode(&enable, &xnackNumNodes, xnackNode));
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
    PM4Queue queue;
    HSAuint32 NumberOfNodes = 10;
    HSAuint32 NodeArray[NumberOfNodes];
    HSAint32 enable = 0;

    EXPECT_SUCCESS(hsaKmtGetXNACKMode(&enable, &NumberOfNodes, NodeArray));
    for (i = 0; i < 2; i++) {
        enable = !enable;
        NumberOfNodes = 10;
        NodeArray[NumberOfNodes];
        EXPECT_SUCCESS(hsaKmtSetXNACKMode(enable, &NumberOfNodes, NodeArray));

        LOG() << "XNACK " << std::boolalpha << enable <<
              " No. gpuids found: " << std::dec << NumberOfNodes << std::endl;

        for (j = 0; j < NumberOfNodes; j++) {
            LOG() << "Creating queue and try to set xnack mode on node: "
                  << NodeArray[j] << std::endl;
            ASSERT_SUCCESS(queue.Create(NodeArray[j]));
            EXPECT_NE(HSAKMT_STATUS_SUCCESS,
                      hsaKmtSetXNACKMode(enable, &NumberOfNodes, NodeArray));
            EXPECT_SUCCESS(queue.Destroy());
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

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

TEST_F(KFDSVMRangeTest, XNACKModeTest) {
    TEST_REQUIRE_ENV_CAPABILITIES(ENVCAPS_64BITLINUX);
    TEST_START(TESTPROFILE_RUNALL);

    HSAuint32 i, j;
    PM4Queue queue;

    for (i = 0; i < 2; i++) {
        HSAuint32 NumberOfNodes = 10;
        HSAuint32 NodeArray[NumberOfNodes];
        bool enable = i;
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

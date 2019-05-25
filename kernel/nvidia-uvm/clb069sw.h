/*******************************************************************************
    Copyright (c) 2014 NVidia Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
*******************************************************************************/
#include "nvtypes.h"

#ifndef _clb069_sw_h_
#define _clb069_sw_h_

#ifdef __cplusplus
extern "C" {
#endif

/* This file is *not* auto-generated. */
#include "clb069.h"

struct _fault_buffer_u032
{
    NvU32   buffer[NVB069_FAULT_BUF_SIZE/(sizeof(NvU32))];
};

typedef struct
{
    NvU8 bufferEntry[NVB069_FAULT_BUF_SIZE];
}NVB069_FAULT_BUFFER_ENTRY;

#ifdef __cplusplus
};     /* extern "C" */
#endif
#endif // _clb069_sw_h


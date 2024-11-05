#ifndef H_CARDANO_APP_ENDIAN
#define H_CARDANO_APP_ENDIAN

#include <stdint.h>

#include "assert.h"
#include "read.h"
#include "write.h"

#define u1be_write(buffer, value) (buffer)[0] = (value);
#define u2be_write(buffer, value) write_u16_be(buffer, 0, value);
#define u4be_write(buffer, value) write_u32_be(buffer, 0, value);
#define u8be_write(buffer, value) write_u64_be(buffer, 0, value);

#define u1be_read(buf) (buf)[0]
#define u2be_read(buf) read_u16_be(buf, 0)
#define u4be_read(buf) read_u32_be(buf, 0)
#define u8be_read(buf) read_u64_be(buf, 0)

#endif  // H_CARDANO_APP_ENDIAN

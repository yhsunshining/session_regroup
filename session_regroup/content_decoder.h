#ifndef __CONTENT_DECODER_H__
#define __CONTENT_DECODER_H__

#include <string>
#include "zlib.h"

class gzip_decoder
{
public:
    gzip_decoder(size_t uncompress_buff_len = 1024);

    ~gzip_decoder();

    bool ungzip(unsigned char* gzdata, size_t gzdata_len, std::string& out_data);

protected:
private:
    const size_t uncompress_buff_len_;
    unsigned char* uncompress_buff_;
};

#endif




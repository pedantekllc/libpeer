#ifndef SDP_H_
#define SDP_H_

#include <stdint.h>
#include <string.h>
#include "config.h"

#define SDP_ATTR_LENGTH 128

#ifndef ICE_LITE
#define ICE_LITE 0
#endif

void sdp_append_h264(char* sdp);
void sdp_append_h264_fec(char* sdp);
void sdp_append_h264_rtx(char* sdp);

void sdp_append_pcma(char* sdp);

void sdp_append_pcmu(char* sdp);

void sdp_append_opus(char* sdp);

void sdp_append_datachannel(char* sdp);

void sdp_create(char* sdp, int b_video, int b_audio, int b_datachannel);

int sdp_append(char* sdp, const char* format, ...);

void sdp_reset(char* sdp);

/* Find the one-byte extension id the SDP maps to `uri` (a=extmap line).
 * Returns 1 and sets *id, or 0 when the SDP carries no such mapping. */
int sdp_find_extmap_id(const char* sdp, const char* uri, uint8_t* id);

#endif  // SDP_H_

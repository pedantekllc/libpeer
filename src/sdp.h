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

void sdp_append_h265(char* sdp);
void sdp_append_h265_fec(char* sdp);
void sdp_append_h265_rtx(char* sdp);

/* One m=video section offering both codecs (H.264 PT 96, H.265 PT 98) on the one SSRC;
 * `rtx` adds an RTX pair per codec (97 apt=96, 99 apt=98). `h265_first` lists H.265
 * first. No RED/ULPFEC variant: FEC sessions offer one codec. */
void sdp_append_h264_h265(char* sdp, int rtx, int h265_first);

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

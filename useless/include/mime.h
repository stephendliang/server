/*
 * SHORT CIRCUIT: MIME -- MIME types.
 *
 * Copyright (c) 2020-2022, Alex O'Brien <3541ax@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <a3/cpp.h>
#include <a3/str.h>

extern "C" {

typedef A3CString ScMimeType;

#define SC_MIME_TYPE_APPLICATION_OCTET_STREAM "application/octet-stream"
#define SC_MIME_TYPE_APPLICATION_JSON         "application/json"
#define SC_MIME_TYPE_APPLICATION_PDF          "application/pdf"
#define SC_MIME_TYPE_IMAGE_BMP                "image/bmp"
#define SC_MIME_TYPE_IMAGE_GIF                "image/gif"
#define SC_MIME_TYPE_IMAGE_ICO                "image/x-icon"
#define SC_MIME_TYPE_IMAGE_JPEG               "image/jpeg"
#define SC_MIME_TYPE_IMAGE_PNG                "image/png"
#define SC_MIME_TYPE_IMAGE_SVG                "image/svg+xml"
#define SC_MIME_TYPE_IMAGE_WEBP               "image/webp"
#define SC_MIME_TYPE_TEXT_CSS                 "text/css"
#define SC_MIME_TYPE_TEXT_JAVASCRIPT          "text/javascript"
#define SC_MIME_TYPE_TEXT_MARKDOWN            "text/markdown"
#define SC_MIME_TYPE_TEXT_PLAIN               "text/plain"
#define SC_MIME_TYPE_TEXT_HTML                "text/html"

ScMimeType sc_mime_from_path(A3CString path);

}

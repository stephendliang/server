/*
 * SHORT CIRCUIT: EVENT BACKEND.
 *
 * Copyright (c) 2022, Alex O'Brien <3541ax@gmail.com>
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

#include <time.h>

#ifdef SC_IO_BACKEND_URING
#include "uring.h"
#elif defined(SC_IO_BACKEND_POLL)
#include "poll_.h"
#else
#error "No valid IO backend is selected."
#endif

void sc_io_backend_init(ScIoBackend*);
void sc_io_backend_destroy(ScIoBackend*);
void sc_io_backend_pump(ScIoBackend*, struct timespec const* deadline);

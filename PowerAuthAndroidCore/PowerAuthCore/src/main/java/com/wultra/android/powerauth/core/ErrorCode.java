/*
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.wultra.android.powerauth.core;

import androidx.annotation.IntDef;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static com.wultra.android.powerauth.core.ErrorCode.Encryption;
import static com.wultra.android.powerauth.core.ErrorCode.OK;
import static com.wultra.android.powerauth.core.ErrorCode.WrongParam;
import static com.wultra.android.powerauth.core.ErrorCode.WrongState;

/**
 * The {@code ErrorCode} constants defines all possible error codes
 * produced by Session class. You normally need to check only
 * if operation ended with OK or not. All other codes are
 * only hints and should be used only for debugging purposes.
 * <p>
 * For example, if the operation fails at WrongState or WrongParam,
 * then it's usually your fault and you're using Session in wrong way.
 */
@Retention(RetentionPolicy.SOURCE)
@IntDef({OK, Encryption, WrongState, WrongParam})
public @interface ErrorCode
{
    /**
     * Everything is OK.
     */
    int OK          = 0;
    /**
     * The method failed on encryption. Whatever that means it's
     * usually very wrong and the UI response depends on what
     * method did you call. Typically, you have to perform retry
     * or restart for the whole process.
     * <p>
     * This error code is also returned when decoding of important
     * parameter failed. For example, if BASE64 encoded value
     * is in wrong format, then this is considered as an attack
     * attempt.
     */
    int Encryption  = 1;
    /**
     * You have called method in wrong Session's state. Usually that
     * means that you're using Session in a wrong way. This kind
     * of error should not be propagated to the UI. It's your
     * responsibility to handle Session states correctly.
     */
    int WrongState  = 2;
    /**
     * You have called method with wrong or missing parameters.
     * Usually this error code means that you're using Session
     * in wrong way and you did not provide all required data.
     * This kind of error should not be propagated to UI. It's
     * your responsibility to handle all user's inputs
     * and validate all responses from server before you
     * ask Session for processing.
     */
    int WrongParam  = 3;
}

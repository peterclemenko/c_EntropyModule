/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file EntropyModule.cpp
 * Contains the implementation of the Entropy file analysis module.
 */

// System includes
#include <sstream>
#include <math.h>

// Framework includes
#include "TskModuleDev.h"

// We process the file 8k at a time
static const uint32_t FILE_BUFFER_SIZE = 8193;

extern "C" 
{
    /**
     * Module initialization function. Receives a string of intialization arguments, 
     * typically read by the caller from a pipeline configuration file. 
     * Returns TskModule::OK or TskModule::FAIL. Returning TskModule::FAIL indicates 
     * the module is not in an operational state.  
     *
     * @param args Initialization arguments.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(std::string& arguments)
    {    
        return TskModule::OK;
    }
    
    /**
     * Module execution function. Receives a pointer to a file the module is to
     * process. The file is represented by a TskFile interface from which both
     * file content and file metadata can be retrieved. Returns TskModule::OK, 
     * TskModule::FAIL, or TskModule::STOP. Returning TskModule::FAIL indicates 
     * the module experienced an error processing the file. Returning TskModule::STOP
     * is a request to terminate processing of the file.
     *
     * @param pFile A pointer to a file to be processed.
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile)
    {
        if (pFile == NULL)
        {
            LOGERROR(L"Entropy module passed NULL file pointer.");
            return TskModule::FAIL;
        }

        try
        {
            unsigned __int8 byte = 0;
            long byteCounts[256];
            memset(byteCounts, 0, sizeof(long) * 256);
            long totalBytes = 0;
            char buffer[FILE_BUFFER_SIZE];
            int bytesRead = 0;

            // Read file content into buffer and write it to the DigestOutputStream.
            do
            {
                memset(buffer, 0, FILE_BUFFER_SIZE);
                bytesRead = pFile->read(buffer, FILE_BUFFER_SIZE);
                for(int i = 0; i < bytesRead; i++){
                    byte = buffer[i];
                    byteCounts[byte]++;
                }
                totalBytes += bytesRead;
            } while (bytesRead > 0);

            double entropy = 0.0;
            for(int i = 0; i<256; i++){
                double p = (double) byteCounts[i]/(double)totalBytes;
                if(p > 0.0)
                    entropy -= p *(log(p)/log(2.0));
            }

            // Post the value to the blackboard
            pFile->addGenInfoAttribute(TskBlackboardAttribute(TSK_ENTROPY, "EntropyModule", "", entropy));
        }
        catch (TskException& tskEx)
        {
            std::wstringstream msg;
            msg << L"EntropyModule - Caught framework exception: " << tskEx.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"EntropyModule - Caught exception: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        return TskModule::OK;
    }

    /**
     * Module cleanup function. This is where the module should free any resources 
     * allocated during initialization or execution.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}
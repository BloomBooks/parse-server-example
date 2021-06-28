/* eslint-disable no-undef */
require("./emails.js"); // allows email-specific could functions to be defined

// This function will call save on every book. This is useful for
// applying the functionality in beforeSaveBook to every book,
// particularly updating the tags and search fields.
Parse.Cloud.define("saveAllBooks", function (request, res) {
    request.log.info("saveAllBooks - Starting.");
    // Query for all books
    var query = new Parse.Query("books");
    query.select("objectId");
    query
        .each(function (book) {
            book.set("updateSource", "saveAllBooks"); // very important so we don't add system:incoming tag
            return book.save(null, { useMasterKey: true }).then(
                function () {},
                function (error) {
                    request.log.error(
                        "saveAllBooks - book.save failed: " + error
                    );
                }
            );
        })
        .then(
            function () {
                request.log.info("saveAllBooks - Completed successfully.");
                res.success();
            },
            function (error) {
                // Set the job's error status
                request.log.error(
                    "saveAllBooks - Terminated with error: " + error
                );
                res.error(error);
            }
        );
});

// A background job to populate usageCounts for languages.
// Also delete any unused language records (previously a separate job: removeUnusedLanguages).
// (tags processing was removed 4/2020 because we don't use the info)
//
// This is scheduled on Azure under bloom-library-maintenance-{prod|dev}-daily.
// You can also run it manually via REST:
// curl -X POST -H "X-Parse-Application-Id: <app ID>" -H "X-Parse-Master-Key: <master key>" -d "{}" https://bloom-parse-server-develop.azurewebsites.net/parse/jobs/updateLanguageRecords
Parse.Cloud.job("updateLanguageRecords", (request, res) => {
    request.log.info("updateLanguageRecords - Starting.");

    var langCounts = {};
    var languagesToDelete = new Array();

    //Make and execute book query
    var bookQuery = new Parse.Query("books");
    bookQuery.limit(1000000); // Default is 100. We want all of them.
    bookQuery.containedIn("inCirculation", [true, undefined]);
    bookQuery.select("langPointers");
    bookQuery
        .find()
        .then((books) => {
            books.forEach((book) => {
                //Spin through each book's languages and increment usage count
                var langPtrs = book.get("langPointers");
                if (langPtrs) {
                    langPtrs.forEach((langPtr) => {
                        var id = langPtr.id;
                        if (!(id in langCounts)) {
                            langCounts[id] = 0;
                        }
                        langCounts[id]++;
                    });
                }
            });

            var langQuery = new Parse.Query("language");
            langQuery.limit(1000000); // Default is 100. We want all of them.
            return langQuery.find();
        })
        .then((languagesToUpdate) => {
            languagesToUpdate.forEach((language) => {
                var newUsageCount = langCounts[language.id] || 0;
                language.set("usageCount", newUsageCount);
                if (newUsageCount === 0) {
                    languagesToDelete.push(language);
                }
            });

            // In theory, we could remove items in languagesToDelete from languagesToUpdate.
            // But there will be so few of them, it doesn't seem worth it.

            return Parse.Object.saveAll(languagesToUpdate, {
                useMasterKey: true,
                success: (successfulUpdates) => {
                    request.log.info(
                        `updateLanguageRecords - Updated usageCount for ${successfulUpdates.length} languages.`
                    );
                },
                // Let any errors bubble up.
            });
        })
        .then(() => {
            if (languagesToDelete.length === 0) return Parse.Promise.as();

            return Parse.Object.destroyAll(languagesToDelete, {
                useMasterKey: true,
                success: (successfulDeletes) => {
                    request.log.info(
                        `updateLanguageRecords - Deleted ${
                            successfulDeletes.length
                        } languages which had no books: ${successfulDeletes.map(
                            (l) => l.get("isoCode")
                        )}`
                    );
                },
                // Let any errors bubble up.
            });
        })
        .then(
            () => {
                request.log.info(
                    "updateLanguageRecords - Completed successfully."
                );
                res.success();
            },
            (error) => {
                if (error.code === Parse.Error.AGGREGATE_ERROR) {
                    error.errors.forEach((iError) => {
                        request.log.error(
                            `Couldn't process ${iError.object.id} due to ${iError.message}`
                        );
                    });
                    request.log.error(
                        "updateLanguageRecords - Terminated unsuccessfully."
                    );
                } else {
                    request.log.error(
                        "updateLanguageRecords - Terminated unsuccessfully with error: " +
                            error
                    );
                }
                res.error(error);
            }
        );
});

// Makes new and updated books have the right search string and ACL.
Parse.Cloud.beforeSave("books", function (request, response) {
    const book = request.object;

    console.log("entering bloom-parse-server main.js beforeSave books");

    // The original purpose of the updateSource field was so we could set system:Incoming on every book
    // when it is uploaded or reuploaded from BloomDesktop without doing so for changes from the datagrid.
    //
    // Now, we also use it to set harvestState to "New" or "Updated" depending on if the book record is new.
    //
    // We also set lastUploaded for old (pre-4.7) BloomDesktops which don't set it themselves.
    let newUpdateSource = book.get("updateSource");
    // Apparently, "dirty" just means we provided it, regardless of whether or not it changed.
    // Careful not to use book.dirty("updateSource") which seems to always be true.
    if (!book.dirtyKeys().includes("updateSource")) {
        // For old BloomDesktops which didn't set the updateSource, we use this hack
        if (
            request.headers["user-agent"] &&
            request.headers["user-agent"].startsWith("RestSharp")
        ) {
            newUpdateSource = "BloomDesktop old";
            book.set("lastUploaded", {
                __type: "Date",
                iso: new Date().toISOString(),
            });
        }
        // direct change on the dashboard (either using "Browser" view or "API Console")
        else if (
            request.headers.referer &&
            request.headers.referer.indexOf("dashboard/apps/BloomLibrary.org") >
                -1
        ) {
            newUpdateSource = "parse dashboard";
        }
        // someone forgot to set updateSource
        else {
            newUpdateSource = "unknown";
        }
        book.set("updateSource", newUpdateSource);
    }
    // As of April 2020, BloomDesktop 4.7 now sets the updateSource to "BloomDesktop {version}".
    if (newUpdateSource.startsWith("BloomDesktop")) {
        // Change came from BloomDesktop upload (or reupload)
        book.addUnique("tags", "system:Incoming");
        if (book.isNew()) {
            book.set("harvestState", "New");
        } else {
            book.set("harvestState", "Updated");
        }

        // Prevent book uploads from overwriting certain fields changed by moderators
        if (request.original) {
            // These columns will not be overwritten unless the new book has truth-y values for them
            // For scalar columns (these are more straightforward than array columns)
            const scalarColumnsWithFallback = [
                "summary",
                "librarianNote",
                "publisher",
                "originalPublisher",
            ];
            scalarColumnsWithFallback.forEach((columnName) => {
                const newValue = book.get(columnName);
                const originalValue = request.original.get(columnName);
                if (!newValue && originalValue) {
                    book.set(columnName, originalValue);
                }
            });

            // These columns are array columns, for which we want to preserve all the pre-existing values
            //
            // tags - For now, we don't bother enforcing that the prefix part (before the colon) is unique (keep it simple for now).
            //        If this is determined to be a requirement, then additional code needs to be added to handle that.
            const arrayColumnsToUnion = ["tags"];
            arrayColumnsToUnion.forEach((columnName) => {
                const originalArrayValue = request.original.get(columnName);
                if (originalArrayValue && originalArrayValue.length >= 1) {
                    book.addAllUnique(columnName, originalArrayValue);
                }
            });

            // Features is able to be changed by moderators, but it's also computed by BloomDesktop. Even if it's empty, keep the BloomDesktop value.
            // My sense is that the auto-computed value is generally more likely to be correct than the value from the DB.
            // The user might've removed all the pages with that feature.
            //
            // langPointers can also be changed by moderators. But it's difficult to keep track of what languages a moderator removed
            // versus what is a newly added language. So for now, we'll live with not modifying langPointers.
        }
    }

    // Bloom 3.6 and earlier set the authors field, but apparently, because it
    // was null or undefined, parse.com didn't try to add it as a new field.
    // When we migrated from parse.com to parse server,
    // we started getting an error because uploading a book was trying to add
    // 'authors' as a new field, but it didn't have permission to do so.
    // In theory, we could just unset the field here:
    // request.object.unset("authors"),
    // but that doesn't prevent the column from being added, either.
    // Unfortunately, that means we simply had to add authors to the schema. (BL-4001)

    var tagsIncoming = book.get("tags");
    var search = (book.get("title") || "").toLowerCase();
    var index;
    const tagsOutput = [];
    if (tagsIncoming) {
        for (index = 0; index < tagsIncoming.length; ++index) {
            var tagName = tagsIncoming[index];
            var indexOfColon = tagName.indexOf(":");
            if (indexOfColon < 0) {
                // From older versions of Bloom, topics come in without the "topic:" prefix
                tagName = "topic:" + tagName;

                indexOfColon = "topic:".length - 1;
            }
            // In Mar 2020 we moved bookshelf tags to their own column so that we could do
            // regex on them without limiting what we could do with other tags
            if (tagName.indexOf("bookshelf") === 0) {
                // Users uploading a book may make a mistake and want to replace the bookshelf.
                // Bloom allows only one bookshelf tag at the moment.
                // Librarians can add more bookshelves, and will have to repeat that operation if a
                // book is re-uploaded with a bookshelf tag.
                // See https://issues.bloomlibrary.org/youtrack/issue/BL-10031.
                const newshelf = tagName.replace("bookshelf:", "");
                if (newUpdateSource.startsWith("BloomDesktop")) {
                    request.object.set("bookshelves", [newshelf]);
                } else {
                    request.object.addUnique("bookshelves", newshelf);
                }
            }
            /* TODO: Mar 2020: we are leaving bookshelf:foobar tags in for now so that we don't have to go into
            the legacy angular code and adjust it to this new system. But once we retire that, we
            should uncomment this else block so that the bookshelf tag is stripped, then run SaveAllBooks()
            to remove it from all the records.*/
            /* TODONE: June 2021: the legacy angular code has been retired. */
            else {
                tagsOutput.push(tagName);
            }

            // We only want to put the relevant information from the tag into the search string.
            // i.e. for region:Asia, we only want Asia. We also exclude system tags.
            // Our current search doesn't handle multi-string searching, anyway, so even if you knew
            // to search for 'region:Asia' (which would never be obvious to the user), you would get
            // a union of 'region' results and 'Asia' results.
            // Other than 'system:', the prefixes are currently only used to separate out the labels
            // in the sidebar of the browse view.
            if (tagName.startsWith("system:")) continue;
            var tagNameForSearch = tagName.substr(indexOfColon + 1);
            search = search + " " + tagNameForSearch.toLowerCase();
        }
    }
    request.object.set("tags", tagsOutput);
    request.object.set("search", search);

    // Transfer bookLineage, which is a comma-separated string, into an array for better querying
    const bookLineage = book.get("bookLineage");
    let bookLineageArray = undefined;
    if (bookLineage) {
        bookLineageArray = bookLineage.split(",");
    }
    request.object.set("bookLineageArray", bookLineageArray);

    var creator = request.user;

    if (creator && request.object.isNew()) {
        // created normally, someone is logged in and we know who, restrict access
        var newACL = new Parse.ACL();
        // According to https://parse.com/questions/beforesave-user-set-permissions-for-self-and-administrators,
        // a user can always write their own object, so we don't need to permit that.
        newACL.setPublicReadAccess(true);
        newACL.setRoleWriteAccess("moderator", true); // allows moderators to delete
        newACL.setWriteAccess(creator, true);
        request.object.setACL(newACL);
    }
    response.success();
});

Parse.Cloud.afterSave("books", function (request) {
    // We no longer wish to automatically create bookshelves.
    // It is too easy for a user (or even us mistakenly) to create them.
    // const bookshelfPrefix = "bookshelf:";
    var book = request.object;
    // book.get("tags")
    //     .filter(function(element) {
    //         return element.indexOf(bookshelfPrefix) > -1;
    //     })
    //     .map(function(element) {
    //         return element.substr(bookshelfPrefix.length);
    //     })
    //     .forEach(function(key) {
    //         var Bookshelf = Parse.Object.extend("bookshelf");
    //         var query = new Parse.Query(Bookshelf);
    //         query.equalTo("key", key);
    //         query.count({
    //             success: function(count) {
    //                 if (count == 0) {
    //                     //Create a new bookshelf to contain this book with default properties
    //                     var bookshelf = new Bookshelf();
    //                     bookshelf.set("key", key);
    //                     bookshelf.set("englishName", key);
    //                     bookshelf.set("normallyVisible", false);
    //                     bookshelf.save(null, { useMasterKey: true }).then(
    //                         function() {},
    //                         function(error) {
    //                             console.log("bookshelf.save failed: " + error);
    //                             response.error(
    //                                 "bookshelf.save failed: " + error
    //                             );
    //                         }
    //                     );
    //                 }
    //             },
    //             error: function(error) {
    //                 console.log("get error: " + error);
    //             }
    //         });
    //     });

    // Now that we have saved the book, see if there are any new tags we need to create in the tag table.
    var Tag = Parse.Object.extend("tag");
    book.get("tags").forEach(function (name) {
        var query = new Parse.Query(Tag);
        query.equalTo("name", name);
        query.count({
            success: function (count) {
                if (count == 0) {
                    // We have a tag on this book which doesn't exist in the tag table. Create it.
                    var tag = new Tag();
                    tag.set("name", name);
                    tag.save(null, { useMasterKey: true }).then(
                        function () {
                            // Success. Nothing else to do.
                        },
                        function (error) {
                            console.log("tag.save failed: " + error);
                            request.log.error("tag.save failed: " + error);
                        }
                    );
                }
            },
            error: function (error) {
                console.log("unable to get tags: " + error);
                request.log.error("unable to get tags: " + error);
            },
        });
    });

    try {
        //send email if this didn't exist before
        // this seemed to work locally, but not on the azure production server,
        // and has been the subject of many bug reports over the years
        //          objectExisted = request.object.existed();
        // so we are working around it this way:
        var createdAt = request.object.get("createdAt");
        var updatedAt = request.object.get("updatedAt");
        var objectExisted = createdAt.getTime() != updatedAt.getTime();

        console.log(
            "afterSave email handling request.object.existed():" +
                request.object.existed()
        );
        console.log(
            "afterSave email handling createdAt:" +
                createdAt +
                " updatedAt:" +
                updatedAt +
                " objectExisted:" +
                objectExisted
        );
        if (!objectExisted) {
            var emailer = require("./emails.js");
            emailer
                .sendBookSavedEmailAsync(book)
                .then(function () {
                    console.log("xBook saved email notice sent successfully.");
                })
                .catch(function (error) {
                    console.log(
                        "ERROR: 'Book saved but sending notice email failed: " +
                            error
                    );
                    // We leave it up to the code above that is actually doing the saving to declare
                    // failure (response.error) or victory (response.success), we stay out of it.
                });
        }
    } catch (error) {
        console.log("aftersave email handling error: " + error);
    }
});

Parse.Cloud.afterSave("downloadHistory", function (request) {
    //Parse.Cloud.useMasterKey();
    console.log(
        "entering bloom-parse-server main.js afterSave downloadHistory"
    );
    var entry = request.object;
    var bookId = entry.get("bookId");

    var booksClass = Parse.Object.extend("books");
    var query = new Parse.Query(booksClass);

    query.get(bookId, {
        success: function (book) {
            var currentDownloadCount = book.get("downloadCount") || 0;
            book.set("downloadCount", currentDownloadCount + 1);
            book.set("updateSource", "incrementDownloadCount"); // very important so we don't add system:incoming tag
            book.save(null, { useMasterKey: true }).then(
                function () {},
                function (error) {
                    console.error("book.save failed: " + error);
                    throw "book.save failed: " + error;
                }
            );
        },
        error: function (object, error) {
            console.log("get error: " + error);
        },
    });
});

// March 2020: The following is only used by legacy (angular) BloomLibrary.
// Return the books that should be shown in the default browse view.
// Currently this is those in the Featured bookshelf, followed by all the others.
// Each group is sorted alphabetically by title.
Parse.Cloud.define("defaultBooks", function (request, response) {
    console.log("bloom-parse-server main.js define defaultBooks function");
    var first = request.params.first;
    var count = request.params.count;
    var includeOutOfCirculation = request.params.includeOutOfCirculation;
    var allLicenses = request.params.allLicenses == true;

    // In legacy bloomlibrary.org (angular), we hide books that aren't CC
    // licensed. This is currently (Mar 2020) just 1% of our books, and also
    // now we have a "use" for even closed-licensed books (reading on the web)
    // so we might not do this in the new (react) blorg.
    const restrictByLicense = (query) => {
        var public = new Parse.Query("books");
        public.startsWith("license", "cc"); // Not cc- so we include cc0

        // We have some books (ok, just one at the moment) that are not CC
        // but that's for a good reason (at the moment, a covid-19 health book
        // where they don't want to allow you to modify it without permission,
        // presumably to ensure that bad info doesn't go out.)
        const overlook = new Parse.Query("books");
        overlook.equalTo("tags", "system:overlookClosedLicense");

        const publicOrOverlook = Parse.Query.or(public, overlook);
        return Parse.Query.and(publicOrOverlook, query);
    };

    let featuredBooksQuery = new Parse.Query("books");
    featuredBooksQuery.equalTo("tags", "bookshelf:Featured");
    if (!includeOutOfCirculation)
        featuredBooksQuery.containedIn("inCirculation", [true, undefined]);

    if (!allLicenses)
        featuredBooksQuery = restrictByLicense(featuredBooksQuery);
    featuredBooksQuery.include("langPointers");
    featuredBooksQuery.include("uploader");
    featuredBooksQuery.ascending("title");
    featuredBooksQuery.limit(1000000); // default is 100, supposedly. We want all of them.
    featuredBooksQuery.find({
        success: function (shelfBooks) {
            var results = [];
            var shelfIds = Object.create(null); // create an object with no properties to be a set
            var resultIndex = 0;
            for (var i = 0; i < shelfBooks.length; i++) {
                if (resultIndex >= first && resultIndex < first + count) {
                    results.push(shelfBooks[i]);
                }
                resultIndex++;
                shelfIds[shelfBooks[i].id] = true; // put in set
            }
            var skip = 0;
            // This function implements a query loop by calling itself inside each
            // promise fulfilment if more results are needed.
            var runQuery = function () {
                let allBooksQuery = new Parse.Query("books");
                if (!includeOutOfCirculation)
                    allBooksQuery.containedIn("inCirculation", [
                        true,
                        undefined,
                    ]);

                if (!allLicenses) {
                    allBooksQuery = restrictByLicense(allBooksQuery);
                }
                allBooksQuery.include("langPointers");
                allBooksQuery.include("uploader");
                allBooksQuery.ascending("title");
                allBooksQuery.skip(skip); // skip the ones we already got
                // REVIEW: would this work? Would it speed things up?  allBooksQuery.limit(count);
                // It looks like maybe we're getting all 1000 books and then only
                // copying "count" books into the results.

                allBooksQuery.find({
                    success: function (allBooks) {
                        skip += allBooks.length; // skip these ones next iteration
                        for (
                            var i = 0;
                            i < allBooks.length && resultIndex < first + count;
                            i++
                        ) {
                            if (!(allBooks[i].id in shelfIds)) {
                                if (resultIndex >= first) {
                                    results.push(allBooks[i]);
                                }
                                resultIndex++;
                            }
                        }
                        if (
                            allBooks.length == 0 ||
                            resultIndex >= first + count
                        ) {
                            // either we can't get any more, or we got all we need.
                            response.success(results);
                            return;
                        }
                        runQuery(); // launch another iteration.
                    },
                    error: function () {
                        response.error("failed to find all books");
                    },
                });
            };
            runQuery(); // start the recursive loop.
        },
        error: function () {
            response.error("failed to find books of featured shelf");
        },
    });
});

// This function is used to set up the fields used in the bloom library.
// Adding something here should be the ONLY way fields and classes are added to parse.com.
// After adding one, it is recommended that you first deploy the modified cloud code
// to a test project, run it, and verify that the result are as expected.
// Then try on the bloomlibrarysandbox (where you should also develop and test the
// functionality that uses the new fields).
// Finally deploy and run on the live database.
// For more information about deploying, see the main README.md.
//
// Currently this will not delete fields or tables; if you want to do that it will have to be
// by hand.
//
// Run this function from a command line like this (with the appropriate keys for the application inserted)
// curl -X POST -H "X-Parse-Application-Id: <App ID>" -H "X-Parse-Master-Key: <Master Key>" https://bloom-parse-server-production.azurewebsites.net/parse/functions/setupTables/
//
// Alternatively, you can use the parse server's dashboard's API Console to run the function:
// parsedashboard.bloomlibrary.org or dev-parsedashboard.bloomlibrary.org.
// Go to the API Console. type=POST, endpoint="functions/setupTables", useMasterKey=yes. Click Send Query.
//
// NOTE: There is reason to believe that using this function to add columns of type Object does not work
// and that they must be added manually (in the dashboard) instead.
Parse.Cloud.define("setupTables", function (request, response) {
    // Required BloomLibrary classes/fields
    // Note: code below currently requires that 'books' is first.
    // Current code supports only String, Boolean, Number, Date, Array, Pointer<_User/Book/appDetailsInLanguage>,
    // and Relation<books/appDetailsInLanguage>.
    // It would be easy to generalize the pointer/relation code provided we can organize so that classes that are
    // the target of relations or pointers occur before the fields targeting them.
    // This is because the way we 'create' a field is to create an instance of the class that has that field.
    // These instances can also be conveniently used as targets when creating instances of classes
    // that refer to them.
    console.log("bloom-parse-server main.js define setupTables function");
    var classes = [
        {
            name: "version",
            fields: [{ name: "minDesktopVersion", type: "String" }],
        },
        {
            name: "books",
            fields: [
                { name: "allTitles", type: "String" },
                // For why the 'authors' field is needed, see http://issues.bloomlibrary.org/youtrack/issue/BL-4001
                { name: "authors", type: "Array" },
                { name: "baseUrl", type: "String" },
                { name: "bookInstanceId", type: "String" },
                { name: "bookLineage", type: "String" },
                { name: "bookOrder", type: "String" },
                { name: "bookletMakingIsAppropriate", type: "Boolean" },
                // In Mar 2020 we moved the bookshelf: tag to this column. Currently incoming books still have
                // the bookshelf: tag, and then beforeSave() takes them out of tags and pushes them in to this
                // array.
                { name: "bookshelves", type: "Array" },
                { name: "copyright", type: "String" },
                { name: "credits", type: "String" },
                { name: "currentTool", type: "String" },
                { name: "downloadCount", type: "Number" },
                { name: "downloadSource", type: "String" },
                { name: "experimental", type: "Boolean" },
                { name: "folio", type: "Boolean" },
                { name: "formatVersion", type: "String" },
                { name: "inCirculation", type: "Boolean" },
                { name: "isbn", type: "String" },
                { name: "keywords", type: "Array" },
                { name: "keywordStems", type: "Array" },
                { name: "langPointers", type: "Array" },
                { name: "languages", type: "Array" },
                { name: "librarianNote", type: "String" },
                { name: "license", type: "String" },
                { name: "licenseNotes", type: "String" },
                { name: "pageCount", type: "Number" },
                { name: "readerToolsAvailable", type: "Boolean" },
                { name: "search", type: "String" },
                { name: "show", type: "Object" },
                { name: "suitableForMakingShells", type: "Boolean" },
                { name: "suitableForVernacularLibrary", type: "Boolean" },
                { name: "summary", type: "String" },
                { name: "tags", type: "Array" },
                { name: "thumbnail", type: "String" },
                { name: "title", type: "String" },
                { name: "originalTitle", type: "String" },
                { name: "tools", type: "Array" },
                { name: "updateSource", type: "String" },
                { name: "uploader", type: "Pointer<_User>" },
                { name: "lastUploaded", type: "Date" },
                { name: "leveledReaderLevel", type: "Number" },
                { name: "country", type: "String" },
                { name: "province", type: "String" },
                { name: "district", type: "String" },
                { name: "features", type: "Array" },
                // Name of the organization or entity that published this book.  It may be null if self-published.
                { name: "publisher", type: "String" },
                // When people make derivative works, that work is no longer "published" by the people who made
                // the shell book. So "publisher" might become empty, or might get a new organization. But we still
                // want to be able to acknowledge what org gave us this shellbook, and list it on their page
                // (indicating that this is a derived book that they are not responsible for). So ideally new
                // shellbooks that have a "publisher" also have that same value in "originalPublisher".
                // "originalPublisher" will never be cleared by BloomDesktop.
                { name: "originalPublisher", type: "String" },
                // This is a "perceptual hash" (http://phash.org/) of the image in the first bloom-imageContainer
                // we find on the first page after any xmatter pages. We use this to suggest which books are
                // probably related to each other. This allows us to link, for example, books that are translations
                // of each other.  (https://www.nuget.org/packages/Shipwreck.Phash/ is used to calculate the phash.)
                { name: "phashOfFirstContentImage", type: "String" },
                // This is the name of the branding project assigned to the book. "Default" means that
                // there isn't any specific branding project assigned to the book.
                { name: "brandingProjectName", type: "String" },
                // BloomDesktop creates bookLineage as a comma-separated string.
                // But we need it to be an array for more complex querying.
                // So beforeSave on books converts it to an array in this field.
                { name: "bookLineageArray", type: "Array" },
                // Fields required by Harvester
                { name: "harvestState", type: "String" },
                { name: "harvesterId", type: "String" },
                { name: "harvesterMajorVersion", type: "Number" },
                { name: "harvesterMinorVersion", type: "Number" },
                { name: "harvestStartedAt", type: "Date" },
                { name: "harvestLog", type: "Array" },
                // End fields required by Harvester
                { name: "internetLimits", type: "Object" },
                { name: "importedBookSourceUrl", type: "String" },
                // Fields required by RoseGarden
                { name: "importerName", type: "String" },
                { name: "importerMajorVersion", type: "Number" },
                { name: "importerMinorVersion", type: "Number" },
                // End fields required by RoseGarden
            ],
        },
        {
            name: "bookshelf",
            fields: [
                { name: "englishName", type: "String" },
                { name: "key", type: "String" },
                { name: "logoUrl", type: "String" },
                { name: "normallyVisible", type: "Boolean" },
                { name: "owner", type: "Pointer<_User>" },
                { name: "category", type: "String" },
            ],
        },
        {
            name: "downloadHistory",
            fields: [
                { name: "bookId", type: "String" },
                { name: "userIp", type: "String" },
            ],
        },
        {
            name: "language",
            fields: [
                { name: "ethnologueCode", type: "String" },
                { name: "isoCode", type: "String" },
                { name: "name", type: "String" },
                { name: "englishName", type: "String" },
                //Usage count determined daily per Parse.com job
                { name: "usageCount", type: "Number" },
            ],
        },
        {
            name: "tag",
            fields: [
                { name: "name", type: "String" },
                //Usage count determined daily per Parse.com job
                { name: "usageCount", type: "Number" },
            ],
        },
        {
            name: "relatedBooks",
            fields: [{ name: "books", type: "Array" }],
        },
        {
            name: "appDetailsInLanguage",
            fields: [
                { name: "androidStoreLanguageIso", type: "String" },
                { name: "title", type: "String" },
                { name: "shortDescription", type: "String" },
                { name: "fullDescription", type: "String" },
            ],
        },
        {
            name: "appSpecification",
            fields: [
                { name: "bookVernacularLanguageIso", type: "String" },
                { name: "defaultStoreLanguageIso", type: "String" },
                { name: "buildEngineJobId", type: "String" },
                { name: "colorScheme", type: "String" },
                { name: "icon1024x1024", type: "String" },
                { name: "featureGraphic1024x500", type: "String" },
                { name: "details", type: "Relation<appDetailsInLanguage>" },
                { name: "owner", type: "Pointer<_User>" },
                { name: "packageName", type: "String" },
            ],
        },
        {
            // must come after the classes it references
            name: "booksInApp",
            fields: [
                { name: "app", type: "Pointer<appSpecification>" },
                { name: "book", type: "Pointer<books>" },
                { name: "index", type: "Integer" },
            ],
        },
    ];

    var ic = 0;
    var aUser = null;
    var aBook = null;
    var anApp = null;
    // If we're updating a 'live' table, typically we will have locked it down so
    // only with the master key can we add fields or classes.
    //Parse.Cloud.useMasterKey();

    var doOne = function () {
        var className = classes[ic].name;
        var parseClass = Parse.Object.extend(className);
        var instance = new parseClass();
        var fields = classes[ic].fields;
        for (var ifld = 0; ifld < fields.length; ifld++) {
            var fieldName = fields[ifld].name;
            var fieldType = fields[ifld].type;
            switch (fieldType) {
                case "String":
                    instance.set(fieldName, "someString");
                    break;
                case "Date":
                    instance.set(fieldName, {
                        __type: "Date",
                        iso: "2015-02-15T00:00:00.000Z",
                    });
                    break;
                case "Boolean":
                    instance.set(fieldName, true);
                    break;
                case "Number":
                    instance.set(fieldName, 1);
                    break;
                case "Array":
                    instance.set(fieldName, ["one", "two"]);
                    break;
                case "Pointer<_User>":
                    instance.set(fieldName, aUser);
                    break;
                case "Pointer<books>":
                    // This and next could be generalized if we get a couple more. User would remain special.
                    instance.set(fieldName, aBook);
                    break;
                case "Pointer<appSpecification>":
                    instance.set(fieldName, anApp);
                    break;

                // It appears this is not used, so we're commenting it out for now. We're not sure if or how it was used previously.
                // case "Relation<books>":
                //     // This and next could be generalized if we have other kinds of relation one day.
                //     var target = aBook;
                //     var relation = instance.relation(fieldName);
                //     relation.add(target);
                //     break;
            }
        }
        instance.save(null, {
            useMasterKey: true,
            success: function (newObj) {
                // remember the new object so we can destroy it later, or use it as a relation target.
                classes[ic].parseObject = newObj;
                // if the class is one of the ones we reference in pointers or relations,
                // remember the appropriate instance for use in creating a sample.
                if (classes[ic].name == "books") {
                    aBook = newObj;
                }
                ic++;
                if (ic < classes.length) {
                    doOne(); // recursive call to the main method to loop
                } else {
                    // Start a new recursive iteration to delete the objects we don't need.
                    ic = 0;
                    deleteOne();
                }
            },
            error: function (error) {
                console.log("instance.save failed: " + error);
                response.error("instance.save failed: " + error);
            },
        });
    };
    var deleteOne = function () {
        // Now we're done, the class and fields must exist; we don't actually want the instances
        var newObj = classes[ic].parseObject;
        newObj.destroy({
            useMasterKey: true,
            success: function () {
                ic++;
                if (ic < classes.length) {
                    deleteOne(); // recursive loop
                } else {
                    cleanup();
                }
            },
            error: function (error) {
                response.error(error);
            },
        });
    };
    var cleanup = function () {
        // We've done the main job...now some details.
        var versionType = Parse.Object.extend("version");
        var query = new Parse.Query("version");
        query.find({
            success: function (results) {
                var version;
                if (results.length >= 1) {
                    // updating an existing project, already has version table and instance
                    version = results[0];
                } else {
                    version = new versionType();
                }
                version.set("minDesktopVersion", "2.0");
                version.save(null, {
                    useMasterKey: true,
                    success: function () {
                        // Finally destroy the spurious user we made.
                        aUser.destroy({
                            useMasterKey: true,
                            success: function () {
                                response.success(
                                    "setupTables ran to completion."
                                );
                            },
                            error: function (error) {
                                response.error(error);
                            },
                        });
                    },
                    error: function (error) {
                        console.log("version.save failed: " + error);
                        response.error("version.save failed: " + error);
                    },
                });
            },
            error: function (error) {
                response.error(error);
            },
        });
    };
    // Create a user, temporarily, which we will delete later.
    // While debugging I got tired of having to manually remove previous "temporary" users,
    // hence each is now unique.
    var rand = parseInt(Math.random() * 10000, 10);
    Parse.User.signUp(
        "zzDummyUserForSetupTables" + rand,
        "unprotected",
        { administrator: false },
        {
            success: function (newUser) {
                aUser = newUser;
                doOne(); // start the recursion.
            },
            error: function (error) {
                response.error(error);
            },
        }
    );
});

// This function expects to be passed params containing an id and JWT token
// from a successful firebase login. It looks for a parse-server identity whose
// username is that same ID. If it finds one without authData (which is how it links
// to the Firebase identity), it creates the authData.
// Otherwise, it does nothing...
// If there is no corresponding parse-server user, the client will
// subsequently call a POST to users which will create the parse-server user with authData.
// If there is a corresponding parse-server user with authData, the POST to users
// will log them in.
Parse.Cloud.define("bloomLink", async function (request, response) {
    let user;
    try {
        var id = request.params.id;
        //console.log(" bloomLink with request: " + JSON.stringify(request));
        const query = new Parse.Query("User");
        query.equalTo("username", id);
        const results = await query.find({ useMasterKey: true });
        if (results.length == 0) {
            // No existing user. Nothing to do.
            response.success("no existing user to link");
            return;
        } else {
            user = results[0];
        }
    } catch (e) {
        response.error(e);
        return;
    }

    // The following code saves authData corresponding to the current token.
    //console.log("bloomLink got user " + JSON.stringify(user));
    const token = request.params.token;
    // Note: at one point I set the id field from user.username. That ought to be
    // the same as id, since we searched for and if necessary created a user with that
    // username. In fact, however, it was always undefined.
    const authData = { bloom: { id: id, token: token } };
    // console.log("bloomLink authdata from params: " + JSON.stringify(authData));

    // console.log(
    //     "bloomLink authdata from user: " + JSON.stringify(user.authData)
    // );

    if (!user.get("authData")) {
        // console.log(
        //     "bloomLink setting user authdata to " + JSON.stringify(authData)
        // );
        user.set("authData", authData, { useMasterKey: true });
        user.save(null, { useMasterKey: true }).then(
            () => {
                // console.log("bloomLink saved user: " + JSON.stringify(user));
                response.success("linked parse-server user by adding authData");
                return;
            },
            (error) => {
                // console.log(
                //     "bloomLink failed to save " + JSON.stringify(error)
                // );
                response.error(error);
                return;
            }
        );
    } else {
        // console.log(
        //     "bloomLink found existing authData: " +
        //         JSON.stringify(user.authData)
        // );
        response.success("existing authData");
        return;
    }
});

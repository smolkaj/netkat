// Copyright 2026 The NetKAT authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "netkat/table_builder.h"

#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "netkat/analysis_engine.h"
#include "netkat/frontend.h"
#include "netkat/table.h"

namespace netkat {
namespace {

using ::absl_testing::StatusIs;

TEST(NetkatTableBuilderTest, BuildEmptyTable) {
  NetkatTable table;
  ASSERT_OK(table.TableBuilder().LogRules().InstallRules());

  AnalysisEngine engine;
  EXPECT_TRUE(
      engine.CheckEquivalent(table.GetPolicy(), Policy::Deny()).IsSuccess());
}

TEST(NetkatTableBuilderTest, BuildTableWithRulesAndDefaultPolicy) {
  NetkatTable table({}, /*accept_default=*/true);
  NetkatTableBuilder builder = table.TableBuilder();
  ASSERT_OK(builder
                .AddRule({
                    .priority = 0,
                    .match = Match("port", 0),
                    .action = Modify("vrf", 1),
                })
                .AddRule({
                    .priority = 0,
                    .match = Match("port", 1),
                    .action = Modify("vrf", 2),
                })
                .LogRules()
                .InstallRules());

  Policy expected =
      Union(Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                  Sequence(Filter(Match("port", 1)), Modify("vrf", 2))),
            Sequence(Filter(!(Match("port", 0) || Match("port", 1))),
                     Policy::Accept()));

  AnalysisEngine engine;
  EXPECT_TRUE(engine.CheckEquivalent(table.GetPolicy(), expected).IsSuccess());
}

TEST(NetkatTableBuilderTest, CustomConstraintPropagatesError) {
  NetkatTable table({[](const NetkatTable::PendingRuleInfo& info) {
    if (info.priority > 10) return absl::InvalidArgumentError("Bad priority.");
    return absl::OkStatus();
  }});
  EXPECT_THAT(table.TableBuilder()
                  .AddRule({
                      .priority = 11,
                      .match = Match("port", 2),
                      .action = Modify("vrf", 3),
                  })
                  .LogRules()
                  .InstallRules(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(NetkatTableBuilderTest, TableBuilderFromExistingTable) {
  NetkatTable table;
  ASSERT_OK(table.TableBuilder()
                .AddRule({
                    .priority = 0,
                    .match = Match("port", 0),
                    .action = Modify("vrf", 1),
                })
                .InstallRules());

  ASSERT_OK(table.TableBuilder()
                .AddRule({
                    .priority = 0,
                    .match = Match("port", 1),
                    .action = Modify("vrf", 2),
                })
                .LogRules()
                .InstallRules());

  Policy expected =
      Union(Union(Sequence(Filter(Match("port", 0)), Modify("vrf", 1)),
                  Sequence(Filter(Match("port", 1)), Modify("vrf", 2))),
            Sequence(Filter(!(Match("port", 0) || Match("port", 1))),
                     Policy::Deny()));

  AnalysisEngine engine;
  EXPECT_TRUE(engine.CheckEquivalent(table.GetPolicy(), expected).IsSuccess());
}

}  // namespace
}  // namespace netkat

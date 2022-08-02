from smda.common.SmdaReport import SmdaReport

import capa.features.extractors.common
import capa.features.extractors.smda.file
import capa.features.extractors.smda.insn
import capa.features.extractors.smda.global_
import capa.features.extractors.smda.function
import capa.features.extractors.smda.basicblock
from capa.features.extractors.base_extractor import FeatureExtractor


class SmdaFeatureExtractor(FeatureExtractor):
    def __init__(self, smda_report: SmdaReport, path):
        super(SmdaFeatureExtractor, self).__init__()
        self.smda_report = smda_report
        self.path = path
        with open(self.path, "rb") as f:
            self.buf = f.read()

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features = []
        self.global_features.extend(capa.features.extractors.common.extract_os(self.buf))
        self.global_features.extend(capa.features.extractors.smda.global_.extract_arch(self.smda_report))

    def get_base_address(self):
        return self.smda_report.base_addr

    def extract_file_features(self):
        yield from capa.features.extractors.smda.file.extract_features(
            self.smda_report, self.buf
        )

        yield from self.global_features

    def get_functions(self):
        yield from self.smda_report.getFunctions()

    def extract_function_features(self, f):
        yield from capa.features.extractors.smda.function.extract_features(f)
        yield from self.global_features

    def get_basic_blocks(self, f):
        yield from f.getBlocks()

    def extract_basic_block_features(self, f, bb):
        yield from capa.features.extractors.smda.basicblock.extract_features(f, bb)
        yield from self.global_features

    def get_instructions(self, f, bb):
        yield from bb.getInstructions()

    def extract_insn_features(self, f, bb, insn):
        yield from capa.features.extractors.smda.insn.extract_features(f, bb, insn)
        yield from self.global_features
